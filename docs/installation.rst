============
Installation
============

**Notice** This is BETA software and is in a testing phase. Do not use it for
production purposes! Do not depend on it for any reason.  During beta testing,
only tech savvy users are encouraged to install this software. As the network
and software matures and it enters production status, user friendly install
packages will be provided.

It is recommended to install software with a package manager when available.  For example, on Debian or Ubuntu::

    sudo aptitude install python-m2crypto virtualenvwrapper

will satisfy all prerequisites.

-------------
Prerequisites
-------------

 * Python - Python2.6 or Python2.7
 * M2Crypto - M2Crypto handles the SSL connections as well as AES file encryption. Use your package manager's version if you can.  For example, on Debian: sudo aptitude install python-m2crypto.

----------
VirtualEnv
----------
virtualenv and virtualenvwrapper are recommended. See http://www.doughellmann.com/projects/virtualenvwrapper/ if you're not familiar with the software. It creates an isolated environment in which you can install packages.

------------------------
Setting Up a Client Node
------------------------

A client install is as simple as installing the ScatterBytes package and registering your client.

Install from PyPI:

If using virtualenv::

    pip install scatterbytes

During the beta stage, it is important that you keep the software updated.  The command to update is::

    pip install --upgrade scatterbytes

This will provide the libraries and scripts to run either a client node or a storage node.

ScatterBytes ships with a CLI program called sbnet.  To see what it can do, type::

    sbnet --help

Register your client.  The first time you do this, an RSA key (for SSL
communication) and an AES key (for encrypting your files) will be generated. By
default, they're stored along with your configuration file. The location of
your configuration file is shown when it is created. Please back these up
somewhere.  If you use the built in file encryption and lose your AES
encryption key, you will not be able to decrypt your files. If you haven't
registered yet, got to https://www.scatterbytes.net and register. Create a
storage node on the website and obtain the Node ID and Recert Code. Next, run
the setup and enter those codes (copy and pate is easiest)::

    sbnet setup-client

-------------------------
Setting Up a Storage Node
-------------------------

A storage node is an https server which runs in the background and listens for connections from both client nodes and the control node. As such, it is important to take precautions to secure the process. The process needs to run reliably and to start automatically should the machine running it reboot.

^^^^^^^^^^^^^^^^^
Debian and Ubuntu
^^^^^^^^^^^^^^^^^


This method starts and runs a storage node as a non-root user.  First, create a new user dedicated to running the storage node::

    sudo adduser sbnode


Next, delete the password so the user can't log in::

    sudo passwd --delete sbnode


While setting things up, switch to that user::

    sudo su - sbnode

Assuming you've installed m2crypto and virtualenvwrapper, setup a virtual environment and install ScatterBytes::

    mkdir .virtualenvs
    mkvirtualenv sb

You should now be in the virtual environment, but just to check::

    deactivate
    workon sb

Install ScatterBytes::

    pip install scatterbytes

If you haven't registered yet, got to https://www.scatterbytes.net and register. Create a storage node on the website and obtain the Node ID and Recert Code. Next, run the setup and enter those codes (copy and pate is easiest)::

    sbnet setup-storage

If all goes well, you're ready to run your storage node.  Pay attention to where your configuration is stored.  It's a good idea to back it up some place safe because it contains your private key and certificate. Finally, setup cron to run your storage node.  If you followed the instructions exactly, your script would be located at ~/.virtualenvs/sb/bin/sbnet.  You'll need the location of the sbnet script so if it's elsewhere, locate it.  Now, edit your crontab::

    crontab -e

It should look like this::

    * * * * * /sbin/start-stop-daemon -S -q -b --name sbnet --startas ~/.virtualenvs/sb/bin/sbnet -- serve

Every minute, cron will check to see if the program is running and start it if it isn't.

To shut down the program, edit the crontab again and comment out the line so it looks like this::

    #* * * * * /sbin/start-stop-daemon -S -q -b --name sbnet --startas ~/.virtualenvs/sb/bin/sbnet -- serve

Then, run a similar command, but use the kill switch::

    /sbin/start-stop-daemon -K --name sbnet
