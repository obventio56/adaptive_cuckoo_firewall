"""
This file contains a slight variation of the main ACF. The only modifications are enabling arbitrary fingerprint lengths
and a somwhat simpler hash function since we do not need to match byte for byte with the tofino C-like representation. 
"""

import crcmod
import numpy as np

"""
Generate fingerprint from int representing 5-tuple
"""
def crc_from_eth(src, fingerprintLength):
    hash2_func = crcmod.predefined.mkCrcFun('crc-32-bzip2')
    return hash2_func(src.to_bytes(13, "little")) & fingerprintLength


class ACF():
    def __init__(self, d, b, c, fingerprintLength):
        self.fingerprintLength = fingerprintLength
        self.c = c
        self.bexp = b
        self.b = b
        self.d = d
        self.tables = np.full((d, self.b, self.c), None, dtype=object).tolist()
        self.backup = np.full((d, self.b, self.c), None, dtype=object).tolist()

    """
    Compute the bucket index for a given fingerprint and table index
    """

    def block_hash(self, x, i):
        hash2_func = crcmod.predefined.mkCrcFun('crc-32-bzip2')
        srcByteString = x.to_bytes(13, "little")
        rotatedByteString = srcByteString[i:] + srcByteString[:i]

        if i == 0:
            assert srcByteString == rotatedByteString
            assert hash2_func(x.to_bytes(13, "little")) % self.b == hash2_func(rotatedByteString) % self.b

        return hash2_func(rotatedByteString) % self.b

    """
    Find an insertion path for x by running BFS. An insertion path represents all the entries that need to 
    move in order to insert x.
    Takes x, the item to insert, and badStates, a list of tables that already have false-positives.
    Returns a list of table indices that represent the path to insert x.
    """

    def find_insertion_path(self, x, badStates=[][:]):
        searchQueue = [[[x, badStates], []]]
        for _ in range(0, 1000):
            if len(searchQueue) < 1:
                print("1000 iterations")
                break

            [[n, nbadStates], path] = searchQueue.pop(0)
            # fingerprint = crc_from_eth(n, es)
            for i in range(0, self.d):
                if i in nbadStates:
                    continue

                # Calculate new path if we inserted into this table
                h = self.block_hash(x, i)
                newPath = path.copy()
                newPath.append(i)

                # If we found a free space, return the path so we can insert
                if self.tables[i][h][0] is None:
                    return newPath

                # Otherwise, push to the queue so we can check the next degree
                [newX, newBadStates] = self.backup[i][h][0]
                searchQueue.append([[newX, newBadStates], newPath])

        # No path found
        return False

    """
    Calculate insertion path and execute insertion operations
    """

    def insert(self, x, badStates=[][:]):

        insertionPath = self.find_insertion_path(x, badStates.copy())

        if insertionPath is False:
            return False

        # Setup initial insertion
        toInsert = [x, badStates.copy()]


        for i in range(0, len(insertionPath)):

            if toInsert is None:
                break

            legTable = insertionPath[i]
            toInsertFingerprint = crc_from_eth(toInsert[0], self.fingerprintLength)
            h = self.block_hash(toInsert[0], legTable)

            toInsertTmp = None
            if self.tables[legTable][h][0] is not None:
                toInsertTmp = self.backup[legTable][h][0].copy()

            self.tables[legTable][h][0] = toInsertFingerprint
            self.backup[legTable][h][0] = toInsert.copy()

            toInsert = toInsertTmp

        return True

    """ Search tables for fingerprint and return indices """

    def membership_index(self, x):
        fingerprint = crc_from_eth(x, self.fingerprintLength)
        for i in range(0, self.d):
            b = self.block_hash(x, i)
            for j in range(0, self.c):
                if self.tables[i][b][j] == fingerprint:
                    return (i, b, j)
        return False

    """ Returns true/false if x in ACF """

    def check_membership(self, x):
        membership_index = self.membership_index(x)
        if membership_index == False:
            return False
        return True

    """ Swaps collision of false_x with different item in same block """

    def adapt_false_positive(self, false_x):

        membershipIndex = self.membership_index(false_x)

        if membershipIndex == False:
            raise "False positive not in ACF"

        (h, b, c) = membershipIndex
        [x, xBadStates] = self.backup[h][b][c]

        # Mark current position as bad
        xBadStates.append(h)

        # Remove from current position
        self.backup[h][b][c] = None
        self.tables[h][b][c] = None

        # Reinsert to try to find new position
        insertSuccess = self.insert(x, xBadStates.copy())

        # Make sure we've resolve the conflict or retry
        if not insertSuccess:
            return insertSuccess
        
        if self.check_membership(false_x) == True:
            return self.adapt_false_positive(false_x)
        
        return True

    """
    Print current state of the filter tables.
    """

    def printState(self):
        print(self.tables)
        print(self.backup)

    """
    Count items in filter. Useful as sanity check.
    """

    def countOccupancy(self):
        count = 0
        for i in range(0, self.d):
            for j in range(0, self.b):
                for k in range(0, self.c):
                    if self.tables[i][j][k] is not None:
                        count += 1
        print("Occupancy is: " + str(count))

    """
    Print the occupancy of each stage in the filter
    """

    def occupancy_stats(self):
        per_table = []
        for i in range(0, self.d):
            total = 0
            full = 0
            for j in range(0, self.b):
                for k in range(0, self.c):
                    total += 1
                    if self.tables[i][j][k] is not None:
                        full += 1
            per_table.append((total, full))
        print(per_table)

    """
    Get delta between CuckooFilter and tofino register state. Used to update tofino registers.
    """

    def getDelta(self, regState):
        delta = []
        for i in range(0, self.d):
            for j in range(0, self.b):
                tableVal = self.tables[i][j][0]
                if tableVal is None:
                    tableVal = 0

                if not tableVal == regState[i][j]:
                    delta.append((i, j, tableVal // 4))
        return delta