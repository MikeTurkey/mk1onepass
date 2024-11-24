..
  2024 Copyright Mike Turkey
  ABSOLUTELY NO WARRANTY, GPLv3 LICENSE
 
  This software is licensed under the terms of the GNU General Public
  License, version 3 (GPLv3), with an additional clause prohibiting the
  use of this software for machine learning purposes.
  Please refer to the LICENSE file for the complete license text
  and additional terms.

  See also
    https://www.gnu.org/licenses/gpl-3.0.html.en  
.. 


mk1onepass
====================================

| mk1onepass created by MikeTurkey
| Version 0.0.3, 24 Nov 2024
| 2024, COPYRIGHT MikeTurkey, All Right Reserved.
| ABSOLUTELY NO WARRANTY. The Licence is based on GPLv3.

Summary
===================================

Timebased One-Time-Password generator.

Synopsis
==================================

| mk1onepass [ --version | --help ]
| mk1onepass [OTPKEY] [-c CONF]
| mk1onepass list [-c CONF]

Quick Start
==================================

  Need oath-toolkit, gnupg(optional)

.. code-block:: console

 $ mkdir ~/.mk1onepass
 $ cd ~/.mk1onepass
 $ emacs ~/.mk1onepass/config.toml
   #   memo. gpg -k --keyid-format long 
   GPGKEYID='1234567890ABCDEF'
 $ emacs ~/.mk1onepass/onetime.toml
   [Otpkeyname]
     secretkey = '1234ABCDXYZ'
     ercode = ['']
 $ gpg -er '1234567890ABCDEF' onetime.toml
 $ mk1onepass list
   Otpkeyname
 $ mk1onepass Otpkeyname
   987654






