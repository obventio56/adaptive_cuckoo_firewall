
import random
import numpy as np
import pathlib
import json
from ACF_experiments import ACF



"""
Generate a random 5 tuple int.
"""
def randomSrc():
    return random.randint(1, 2**104)


configurations = [(2, 7, 1), (3, 7, 1), (4, 7, 1),
                  (5, 7, 1), (3, 8, 1), (3, 9, 1), (3, 10, 1)]


filterSize = 13*512
iterations = 5
if __name__ == "__main__":

    for s_count in range(2, 18):
        occupancy = s_count*5
        adaptation_result = []

        for _ in range(0, iterations):

            # Create new filter
            testCuckoo = ACF(
                13, 512, 1, 0xff)

            # Insert items until we reach the desired occupancy
            n_insert = int((filterSize*occupancy/100))
            i_st = set()

            reachedCapacity = True
            while len(i_st) < n_insert:
                x = randomSrc()
                i_st.add(x)

                if not testCuckoo.insert(x):
                    reachedCapacity = False
                    print("Did not reach capacity")

            if not reachedCapacity:
                break

            FP = 0
            src_lst = list(i_st)
            while True:
                x = src_lst[FP % len(src_lst)]

                if not testCuckoo.adapt_false_positive(x):
                    break

                # assert testCuckoo.check_membership(x) == False
                FP += 1

            print(FP)
            adaptation_result.append(FP)

        print(s_count*5, sum(adaptation_result) /
              len(adaptation_result), adaptation_result)

        pathlib.Path("results/capacity{}.json".format(s_count)).write_text(json.dumps((s_count*10, sum(adaptation_result) /
                                                                                             len(adaptation_result), adaptation_result)))
