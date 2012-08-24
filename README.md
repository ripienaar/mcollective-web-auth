What?
=====

A very basic two factor authentication service for mcollective.

*This is a proof of concept to demonstrate the basic design of
such a system and not for wider use just yet.*

A webservice runs centrally and has a private key.  Users log
into the webservice and authenticates using duo security:

    % mco login
    User Name: rip
    Password: ******
    Performing two factor authentication against webservice and duo security....
    Token saved to /home/rip/.mcollective.token valid till Thu Aug 23 22:24:02 +0100 2012

Once logged in every mcollective client request is submitted to the
webservice which would validate the token and and return a signature
and encrypted user name.

The client will then submit the request including the secure
hashes and encrypted username to the network.  Each receiving
node will decrypt the data using the public key for the webservice
if succesfull the request gets dispatched and replies get sent
direct to the client.

This way there is a central authority thats authorative for
any and all mcollective requests on the entire network.  There
is only 1 set of SSL keys on the network which makes securing
the whole easier.

The end result is that the identity of users are not tied to
a certificate file name or unix user but to whatever the webservice
declares the user name is.  This username is used throughout in
all Auditing and Authorization done by mcollective

Shortcomings of the POC
=======================

 * Does not use SSL
 * Registration does not work
 * Long running MC clients must be able to use their own certs and authorize their own requests so for monitoring the webservice is not a SPOF

The last 2 items are related, it will need the ability that if the 
client specifies it has it's own private key then it should not rely
on the webservice for auth.  On the servers you would just put the
public key for these hosts in addition to the one of the webservice.

Authorization plugins will still work as always, thus just restrict 
this new certificate to the monitoring related agents.

Future Ideas
============

Past the POC the following can be done:

 * Submit the whole request to the webservice, do central RBAC by just not signing requests that does not pass RBAC
