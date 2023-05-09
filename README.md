# Implementing Adaptive Cuckoo Firewall for Programmable Switch 

This repository contains code to accompany a poster presented at the NSDI '23 student poster session. You can view:
- [A copy of the poster](poster.png)
- [The written poster proposal](poster_proposal.pdf)

### Repository structure
- `tofino_poc` - p4 code + controller logic as well as a basic host 
- `ACF.py` - cuckoo filter class
- `experiments` - code to generate charts in poster

### Tofino Proof of Concept

We've created an implementation of a version our design for tofino switch with 3 stages. The code consists of a few parts:
- P4 code for a simple 3 stage filter using register arrays and a single CRC hash function
- Controller to handle ACF insertions and cuckooing
- Host to send ICMP packets
- Client to send traffic through switch to host

All of the controller/host/client code is packaged in one python file within `tofino_poc/tests/run_caida_trace.py` to use the Tofino test harness

#### To run the program:
0. Prepare trace. We've provided a utility `preprocess_caida_trace.py` that takes a PCAP file and extracts 5-tuples for each packet. Please run this on your test data and set `TRACE_PATH` in `/tofino_poc/run_caida_trace.py` to point to the output.

1. Set variables:
  ```
   export REPO_PATH=<absolute path to repo parent folder>
   export BF_SDE_PATH=<absolute path to bf sde root folder>
  ```
   **ALSO** set `REPO_PATH` variable in `/tofino_poc/run_caida_trace.py`
  
2. Compile p4 program
  ```
  sudo -E ./tofino_poc/compile.sh
  ```
3. Start switchd (in new terminal)
  ```
  sudo -E $BF_SDE_PATH/run_switchd.sh -p src
  ```
4. Start tofino model (in new terminal)
  ```
  $BF_SDE_PATH/run_tofino_model.sh -p src  --log-dir $REPO_PATH/tofino_acf_firewall/tofino_poc/logs
  ```
5. Start test
  ```
  sudo -E $BF_SDE_PATH/run_p4_tests.sh -p src -t $REPO_PATH/tofino_acf_firewall/tofino_poc/tests
  ```

### Experiments

Our poster has three major results which each corrosponds to a python file used to generate it. Since the properties of the design are independent from interfacing with the switch, these experiments do not require the Tofino simulation. 

1. Number of Supported Adaptations at Occupancy -> `experiments/adaptations_at_occupancy.py`
2. Optimal Stage Count -> `experiments/optimal_stage_count.py`
3. CAIDA Trace False Positve Rate -> `experiments/CAIDA_trace_fp_rate.py`

#### Making graphs

Each experiment script produces output in the `results` folder. We also have scripts to generate graphs from these results. That code can be found in `experiments/make_graphs`. The usage of each script is slightly different so it is best to read the file first. 

