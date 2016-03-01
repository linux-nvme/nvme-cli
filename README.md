# nvme-cli
NVM-Express user space tooling for Linux.

To install, run:

  # make && make install

If not sure how to use, find the top-level documentation with:

  # man nvme

Or find a short summary with:

  # nvme help

## Distro Support

### Fedora

nvme-cli is available in Fedora 23 and up.  Install it with your favorite
package manager.  For example:

    $ sudo dnf install nvme-cli

### Ubuntu

nvme-cli is supported in the Universe package sources for Xenial for
many architectures. For a complete list try running:
  ```
  rmadison nvme-cli
   nvme-cli | 0.3-1 | xenial/universe | source, amd64, arm64, armhf, i386, powerpc, ppc64el, s390x
  ```  
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
   
### AlpineLinux

nvme-cli is tested on AlpineLinux 3.3.  Install it using:

    # akp update && apk add nvme-cli nvme-cli-doc
    
    the "list" command will not work unless you installed udev for some reason.
    ```
    # nvme list
    nvme-list: libudev not detected, install and rebuild.
    ```
    
    if you just use the device you're after, it will work flawless.
    ```
    # nvme smart-log /dev/nvme0
Smart Log for NVME device:/dev/nvme0 namespace-id:ffffffff
critical_warning                    : 0
temperature                         : 49 C
available_spare                     : 100%
    ```
   
### openSUSE Tumbleweed

nvme-cli is available in openSUSE Tumbleweed. You can install it using zypper.
For example:

    $ sudo zypper install nvme-cli

### Other Distros

TBD
