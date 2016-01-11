# nvme-cli
NVM-Express user space tooling for Linux.

To install, run:

  # make && make install

If not sure how to use, find the top-level documentation with:

  # man nvme

Or find a short summary with:

  # nvme help

## Distro Support
### Ubuntu

A Debian based package for nvme-cli is currently maintained as a
Ubuntu PPA. Right now there is support for Trusty, Vivid and Wiley. To
install nvme-cli using this approach please perform the following
steps:
   1. Add the sbates PPA to your sources. One way to do this is to run
   ```
   sudo add-apt-repository ppa:sbates
   ```
   2. Perform an update of your repository list:
   ```
   sudo apt-get update
   ```
   3. Get nvme-cli!
   ```
   sudo apt-get install nvme-cli
   ```
   4. Test the code.
   ```
   sudo nvme list
   ```
   In the case of no NVMe devices you will see
   ```
   No NVMe devices detected.
   ```
   otherwise you will see information about each NVMe device installed
   in the system.
### Other Distros

TBD
