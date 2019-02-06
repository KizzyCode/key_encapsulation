[![BSD 2-Clause License](https://img.shields.io/badge/License-BSD--2--Clause-blue.svg)](https://opensource.org/licenses/BSD-2-Clause)
[![MIT License](https://img.shields.io/badge/License-BSD--2--Clause-blue.svg)](https://opensource.org/licenses/MIT)
[![Travis CI](https://travis-ci.org/KizzyCode/kync.svg?branch=master)](https://travis-ci.org/KizzyCode/kync)
[![Appveyor](https://ci.appveyor.com/api/projects/status/github/KizzyCode/kync?svg=true)](https://ci.appveyor.com/project/KizzyCode/kync)

# KyNc
This crate is a Rust interface to [KyNc](https://github.com/KizzyCode/kync/blob/master/Kync.asciidoc) plugins.


## What is the purpose of KyNc and this crate?
Short: Abstracting key management away.

Long: [KyNc defines](https://github.com/KizzyCode/kync/blob/master/Kync.asciidoc) and this crate implements a plugin
interface, that allows to use plugins for key management. Your app generates a random key to do something and the user
can specify how this key is stored. Some users may install a plugin that uses GnuPG to seal the key, some people may
load a plugin that uses a password to encrypt the key, and some companies may use their own custom plugins that
integrate perfectly in their environment. And they only need to do it once – because if a specific plugin has been
created, it can be used with all applications that implement KyNc.


## ⚠️ State ⚠️
This library and standard are alpha and neither audited nor frozen. Use at your own risk and feel free to contribute.


## Known plugins that implement KyNc
. Currently none – but I'm working on a GnuPG plugin to utilize my Yubikey 🙃