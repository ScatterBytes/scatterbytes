=====
Intro
=====

----------------
Network Overview
----------------

ScatterBytes is a network storage system designed to distribute data and copies
of that data across the internet. Unlike conventional systems which transfer
and store data in data centers requiring high transfer and storage capacity at
those centers, ScatterBytes transfers data directly between peers on the
network, which distributes both the transfer routes and the storage locations.

-----
Nodes
-----

There are three node types on the network: the client node, the storage node,
and the control node. The client node uploads and downloads data to and from
the network.  It is the "consumer".  The storage node stores data uploaded from
the client, sends data downloaded by the client, and replicates data as
requested by the control node. The control node coordinates activity between
the client and storage nodes and monitors the network to maintain integrity.

----------
Redundancy
----------

Redundancy is configurable by use of pre-defined volumes. A client may create
any number of volumes, which also function as a namespace for file names. The
mirror count attribute specifies the number of times the file chunks are to be
copied to additional storage nodes. One may add no redundancy or as much
redundancy as the network will support.  For instance, a mirror count of 1
will maintain 2 copies (original + 1) of each file chunk.

-------------
Data Security
-------------

By default, the ScatterBytes client encrypts all data using AES 256
encryption. This means the client is the *only* one that can read the data
uploaded.  Neither the storage nodes or the control node can read the stored
data. In addition, the client may opt to use his own encryption software and
disable the built in encryption.

----------------------
Communication Security
----------------------

The ScatterBytes network communication is built on Transport Layer Security
(TLS) and X.509 certificates. Absolutely all communication is encrypted via
TLS and all nodes identities verified via X.509 certificates.

--------
Payments
--------

Rates are stated in gigabyte-months with a month being 30 24 hour days. Actual
computed rates are based on byte-hours.

Client nodes pay per gigabyte-month per storage node. For instance, if the
current storage rate is 2 cents per gigabyte-month (30 day month) and the
client opts to mirror the data 2 times, the cost would be 6 cents * number of
gigabyte-months used. Initially, only storage costs apply though download and
query costs will likely be applied to balance the system.

Storage nodes are paid to store data.  The current rate is 75% of the rate
charged to the client. For instance, if a storage node stored 1 terabyte of
data for 30 days at 0.015 cents per gigabyte-hour, the payment would be
$15.36. When a download rate is charged, the storage node will be compensated
as well.
