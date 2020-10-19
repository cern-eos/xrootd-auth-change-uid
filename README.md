XRootD Authentication Plugin to Change the Filesystem Uid
==========================================================

This project contains a plugin for the **XRootD** server which manages the
authentication by setting the FS uid of the user who made the request,
hence providing regular POSIX access.

Setup
======

This plugin is loaded by the XRootD Server. In order to accomplish this, it is
necessary to indicate the server where the plugin is by adding the following
lines to the server's configuration file:

  ofs.authlib /path/to/libAuthChangeFsUid.so
  ofs.authorize

An optional delegate authentication library can also be set for additional
authentication. This is done by adding the following line to the referred
configuration file:

  authchangefsuid.authlib /path/to/delegateAuthLib.so

If the intrinsic default Acc library of XROOTD should be used add:

  authchangefsuid.authlib default
