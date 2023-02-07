#balenalib/<hw>-<distro>-<lang_stack>:<lang_ver>-<distro_ver>-(build|run)-<yyyymmdd>
#This installs Debian (version bullseye) with Python 3.9
FROM balenalib/raspberrypi3-debian:bullseye-build

#Get Pip
RUN curl -sS https://bootstrap.pypa.io/get-pip.py | python3

#Force cryptography to be install via piwheels so that mitmproxy will build
RUN pip3 install cryptography -i https://www.piwheels.org/simple
#Force numpy to be installed as it breaks when getting from pip
RUN pip3 install numpy -i https://www.piwheels.org/simple
#Force psutil install as it doesn't like pip
RUN pip3 install psutil -i https://www.piwheels.org/simple

#Install the other packages we need
RUN install_packages hostapd dhcpd isc-dhcp-server tshark iptables rustc iw rfkill kbd macchanger

# Set our working directory
WORKDIR /pwnpi

# Copy requirements.txt first for better cache on later pushes
COPY pythonrequirements.txt pythonrequirements.txt

# Install requirements
RUN pip3 install -r pythonrequirements.txt

# This will copy all files in our root to the working  directory in the container
COPY . ./

# Enable udevd so that plugged dynamic hardware devices show up in our container.
ENV UDEV=1

#Install the last parts to get numpy working, we need to add a previous repo
RUN echo 'deb http://deb.debian.org/debian/ buster main' >> /etc/apt/sources.list
RUN echo 'deb http://deb.debian.org/debian/ buster-updates main' >> /etc/apt/sources.list
RUN apt update
RUN apt-get install libatlas-base-dev

# main.py will run when container starts up on the device
#CMD ["python3" , "/pwnpi/main.py"]
CMD ["tail", "-f", "/dev/null"]
