# nvme-cli
NVM-Express user space tooling for Linux.

To build and install:
```
$ autogen.sh && ./configure --prefix=$your_prefix
$ make && make install   # install to $your_prefix
$ make rpm               # or generate an RPM and install that
```

If libudev headers are not installed (now usually a part of systemd-devel),
then the "nvme list" command will not list the present devices but the rest 
of the ioctl commands will work as expected.

If not sure how to use, find the top-level documentation with:
    ```
    $ man nvme
    ```

Or find a short summary with:
    ```
    $ nvme help
    ```

To see what NVME devices are on the system:
    ```
    $ sudo nvme list
    ```

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
 
### AlpineLinux

nvme-cli is tested on AlpineLinux 3.3.  Install it using:
    ```
    $ akp update && apk add nvme-cli nvme-cli-doc
    ```

### openSUSE Tumbleweed

nvme-cli is available in openSUSE Tumbleweed. You can install it using zypper:
    ```
    $ sudo zypper install nvme-cli
    ```

### Arch Linux

Install from AUR, e.g.:
```
    $ yaourt -S nvme-cli-git
```

### Other Distros

Please file an issue to track and/or request distro support.
