# nvme-cli
NVM-Express user space tooling for Linux.

To install, run:

  # make && make install

If not sure how to use, find the top-level documentation with:

  # man nvme

Or find a short summary with:

  # nvme help

## Distro Support
### Ubunutu

A Debian based package for nvme-cli is currently maintained as a
Ubunuta PPA. To install nvme-cli using this approach please perform
the following steps:
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
### Other Distros

TBD
