import random
import crcmod
import numpy as np
import pathlib
import json
from ACF_experiments import ACF

"""
Generate a random MAC address.
"""

def randomSrc():
    return random.randint(1, 2**104)

"""
Generate fingerprint from int representing 5-tuple
"""
def crc_from_eth(src, fingerprintLength):
    hash2_func = crcmod.predefined.mkCrcFun('crc-32-bzip2')
    return hash2_func(src.to_bytes(13, "little")) & fingerprintLength

configurations = [(2, 7, 1), (3, 7, 1), (4, 7, 1),
                  (5, 7, 1), (3, 8, 1), (3, 9, 1), (3, 10, 1)]


filterSize = 2048
iterations = 10
if __name__ == "__main__":

    for s_count in [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]:
        occupancy_result = []

        for _ in range(0, iterations):
            left = 0
            right = 99

            while True:

                estimate = left + int((right - left) / 2)
                if estimate == left or estimate == right:
                    print(estimate)
                    occupancy_result.append(estimate)
                    break

                # Create new filter
                testCuckoo = ACF(
                    s_count, int(filterSize/s_count), 1, 0xff)

                # Insert items until we reach the desired occupancy
                achievedCapacity = True
                n_insert = int(filterSize*estimate/100)
                i_st = set()

                while len(i_st) < n_insert:
                    x = randomSrc()
                    i_st.add(x)

                    if not testCuckoo.insert(x):
                        achievedCapacity = False
                        break

                if not achievedCapacity:
                    right = estimate
                else:
                    left = estimate

        print(s_count, sum(occupancy_result) /
              len(occupancy_result), occupancy_result)

        pathlib.Path("results/stages{}.json".format(s_count)).write_text(json.dumps((s_count, sum(occupancy_result) /
                                                                                  len(occupancy_result), occupancy_result)))
