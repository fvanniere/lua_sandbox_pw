/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/** @brief Test module configuration @file */

#define TEST_MODULE_PATH \
"path  = [[${TEST_MODULE_PATH};${TEST_IOMODULE_PATH};/usr/lib/luasandbox/io_modules/?.lua;/usr/lib/luasandbox/modules/?.lua]]\n" \
"cpath = [[${TEST_MODULE_CPATH};${TEST_IOMODULE_CPATH};/usr/lib/luasandbox/io_modules/?.so;/usr/lib/luasandbox/modules/?.so]]\n" \
"instruction_limit = 0\n" \
"memory_limit = 0\n"
