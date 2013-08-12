ScatterBytes
============

A highly distributed data storage network - the thunderstorm of cloud storage!

.. ATTENTION::
   Deployment is underway!  Once the ScatterBytes network is running, this
   notice will be removed.


This package contains an implementation of a client and storage node to the
ScatterBytes network. For more about the scatterbytes network, see
https://www.scatterbytes.net.

Introduction
------------

ScatterBytes stores your data remotely, securely, and redundantly. Traditional
"cloud" storage services store data in a handful of data centers. This approach
requires large "pipes" to move data in and out. By contrast, ScatterBytes
stores data on geographically distributed peer run devices. This approach
allows for the data transfer load to be distributed among the peers, enabling
high transfer rates without the need for big pipes and for better network
resiliency in the case of network path failures

Peer run nodes (storage nodes) store chunks of data and replicate that data
with other peers.  These nodes are constantly monitored for availability and
health and compensated (currently with Bitcoin payments) for the amount and
availability of data they store. Any device with a constant network connection
can be a storage node.

All data is encrypted by the client before it is uploaded using the client's
256 bit AES key so ONLY the client can read that data.  In addition, all
communication is encrypted using SSL and authenticated using signed X.509
certificates. 

Requirements
------------

- Python 2.6 or 2.7

- M2Crypto:  All of the cryptographic functionality is provided by M2Crypto,
  which is required by both client and storge nodes. It is used to encrypt all
  communications, encrypt files, and identify (using X.509 certificates) all
  nodes on the network.


Installing
----------

For a Debian based system, installing the deb from https://www.scatterbytes.net
will install the ScatterBytes software and add a repository for APT. From the
repository, the scatterbytes-server package will configure your system to run a
storage node.

For a client only install, assuming Python and M2Crypto are installed, the
standard distutils setup, "python setup.py install", will work just fine. Also,
the package does not need to be installed to run as long as it is in the Python
Path.

License
-------

ScatterBytes is distributed under the MIT License.
http://opensource.org/licenses/MIT
