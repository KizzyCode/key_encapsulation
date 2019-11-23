[![docs.rs](https://docs.rs/kync/badge.svg)](https://docs.rs/kync)
[![License BSD-2-Clause](https://img.shields.io/badge/License-BSD--2--Clause-blue.svg)](https://opensource.org/licenses/BSD-2-Clause)
[![License MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![crates.io](https://img.shields.io/crates/v/kync.svg)](https://crates.io/crates/kync)
[![Download numbers](https://img.shields.io/crates/d/kync.svg)](https://crates.io/crates/kync)
[![Travis CI](https://travis-ci.org/KizzyCode/kync.svg?branch=master)](https://travis-ci.org/KizzyCode/kync)
[![AppVeyor CI](https://ci.appveyor.com/api/projects/status/github/KizzyCode/kync?svg=true)](https://ci.appveyor.com/project/KizzyCode/kync)
[![dependency status](https://deps.rs/crate/kync/0.2.0/status.svg)](https://deps.rs/crate/kync/0.2.0)


# KyNc
This crate is a Rust interface to
[KyNc](https://github.com/KizzyCode/kync/blob/master/Kync.asciidoc) plugins.


## What is the purpose of KyNc and this crate?
Short: Protecting sensible data in a user defined/context sensitive way.

Long: [KyNc defines](https://github.com/KizzyCode/kync/blob/master/Kync.asciidoc) a plugin API that
allows your app to load context specific or user selected plugins to protect your app's secrets. If
your app e.g. uses a login token or a database master key, it can be protected in a user controlled
and context specific way. On macOS/iOS the keychain may be the way to go, on Linux some users may
want to use GnuPG to protect the secret etc. Some people and companies may even implement their own 
custom plugins that specifically suit their needs.

The main advantage of a unified API like KyNc is that once you have a (custom) plugin you can load
it into every app that wants to store secrets and implements KyNc.


## ⚠️ State ⚠️
This library and standard are alpha and neither audited nor frozen. Use at your own risk and feel
free to contribute.


## Known plugins that implement KyNc
. Currently none – but I'm working on a GnuPG plugin to utilize my Yubikey 🙃

If you want to implement your own plugin, take a look at
[the specification](https://github.com/KizzyCode/kync/blob/master/Kync.asciidoc), the 
[`kync_test_plugin`](https://github.com/KizzyCode/kync/tree/master/kync_test_plugin) and the
contained `kync.h`-file.