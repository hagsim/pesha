# Pesha

This repo contains my attempted solution at the following project:
[B5] PE Memory hash
Given a PE file, parse its relocation table and use it to build a hash (e.g., sha2) of the application code section with all relocated slots set to zeros.
Then take a snapshot of the memory of a system where the application is running, dump the process memory and compute the same hash. Verify that the two match.

# Requirements
 - The program uses Volatility to extract information from the memorydump, therefor Volatility must be installed and available as "vol.py".
 - For python, please make sure that argparse is installed.

# Example usage
