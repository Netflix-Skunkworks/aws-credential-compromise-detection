# Detecting Credential Compromise in AWS

This following code is an example implementation of the method described [here](docs/us-18-Bengtson-Detecting-Credential-Compromise-In-AWS.pdf)

## Getting Started

To get started, clone the repository and `pip` install the package

`pip install .`

## Running the program

To understand what commands exist, run:

`detect --help`

```detect --help
Usage: detect [OPTIONS]

  Detect off instance key usage

Options:
  -v, --verbosity LVL  Either CRITICAL, ERROR, WARNING, INFO or DEBUG
  --config YAML        Configuration file to use.
  --directory TEXT     Path to directory with CloudTrail files  [required]
  --version            Show the version and exit.
  --help               Show this message and exit.
```

Copy your CloudTrail to a local directory.  All files must be in the same folder.

To run the code over your local CloudTrail files, run the following command:

`detect --verbosity INFO --directory <path_to_cloudtrail_files>`

You should see something like the following output:

```detect --verbosity INFO --directory /tmp/cloudtrail/
Detecting AWS Key Usage off instance...
Processing file: /tmp/cloudtrail/123456789123_CloudTrail_us-west-2_20180404T0000Z_1gye90eoWO1b1QRG.json.gz
Processing file: /tmp/cloudtrail/123456789123_CloudTrail_us-west-2_20180404T0005Z_LNYW3Mic2zLWETkX.json.gz
Processing file: /tmp/cloudtrail/123456789123_CloudTrail_us-west-2_20180404T0010Z_7V7xcXO6UzW77LwK.json.gz
Processing file: /tmp/cloudtrail/123456789123_CloudTrail_us-west-2_20180404T0015Z_LAJ1Yb1bNyYSWXXA.json.gz
Processing file: /tmp/cloudtrail/123456789123_CloudTrail_us-west-2_20180404T0020Z_t9rx7kgzBtItJhMy.json.gz
Processing file: /tmp/cloudtrail/123456789123_CloudTrail_us-west-2_20180404T0025Z_M0HzhcOov89xY6w3.json.gz
Processing file: /tmp/cloudtrail/123456789123_CloudTrail_us-west-2_20180404T0030Z_CBWEoVc6o54WtOg0.json.gz
Processing file: /tmp/cloudtrail/123456789123_CloudTrail_us-west-2_20180404T0035Z_ksL7pEasuX6bWPHX.json.gz
Processing file: /tmp/cloudtrail/123456789123_CloudTrail_us-west-2_20180404T0040Z_LwJdh1z4HGTH0XJH.json.gz
Processing file: /tmp/cloudtrail/123456789123_CloudTrail_us-west-2_20180404T0045Z_UWCcHKGZO8tndQxi.json.gz
Processing file: /tmp/cloudtrail/123456789123_CloudTrail_us-west-2_20180404T0050Z_bKEN9jPfv0zTVph0.json.gz
Processing file: /tmp/cloudtrail/123456789123_CloudTrail_us-west-2_20180404T0055Z_zj6ZG2zOPpCXKzJX.json.gz
Processing file: /tmp/cloudtrail/123456789123_CloudTrail_us-west-2_20180404T0100Z_UiWFT9ORqfYtdppO.json.gz
Processing file: /tmp/cloudtrail/123456789123_CloudTrail_us-west-2_20180404T0105Z_mhO8z0wHjDupnp6Y.json.gz
.......
Compromised Credential: arn:aws:sts::123456789123:assumed-role/testRole1/i-asdf1234adsf1234a - Source IP: 67.178.52.232 
Compromised Credential: arn:aws:sts::123456789123:assumed-role/testRole1/i-asdf1234adsf1234a - Source IP: 67.178.52.232 
Compromised Credential: arn:aws:sts::123456789123:assumed-role/testRole1/i-asdf1234adsf1234a - Source IP: 67.178.52.232 
Compromised Credential: arn:aws:sts::123456789123:assumed-role/testRole1/i-asdf1234adsf1234a - Source IP: 67.178.52.232 
........
Processing file: /tmp/cloudtrail/123456789123_CloudTrail_us-west-2_20180404T2130Z_OR96it0GfXSDfECJ.json.gz
Processing file: /tmp/cloudtrail/123456789123_CloudTrail_us-west-2_20180404T2135Z_FBudvwUxhu9dv1yh.json.gz
Processing file: /tmp/cloudtrail/123456789123_CloudTrail_us-west-2_20180404T2140Z_w9fFoLIdlCXwnpgc.json.gz
Processing file: /tmp/cloudtrail/123456789123_CloudTrail_us-west-2_20180404T2145Z_achBqdC1o6d6wnQG.json.gz
Potential for a new IP to be seen: arn:aws:sts::123456789123:assumed-role/testRole2/i-1234asdf1224asdf1
........
Processing file: /tmp/cloudtrail/123456789123_CloudTrail_us-west-2_20180404T2340Z_GqdLsMcsTkRRxWev.json.gz
Processing file: /tmp/cloudtrail/123456789123_CloudTrail_us-west-2_20180404T2345Z_Ln5pCyldci0nn07X.json.gz
Processing file: /tmp/cloudtrail/123456789123_CloudTrail_us-west-2_20180404T2350Z_hW7tWtYiwbbZdSqd.json.gz
Processing file: /tmp/cloudtrail/123456789123_CloudTrail_us-west-2_20180404T2355Z_q5nS1nqvbGwBN0yT.json.gz
```
