#
# Copyright (C) 2018-2019 QuasarApp.
# Distributed under the lgplv3 software license, see the accompanying
# Everyone is permitted to copy and distribute verbatim copies
# of this license document, but changing it is not allowed.
#

TEMPLATE = subdirs
CONFIG += ordered

SUBDIRS += \
    pe-parser-library \
    dump-pe



#CQtDeployer.depends=QuasarAppLib
#CQtDeployer.depends=Deploy

#QuasarAppLib.file = $$PWD/QuasarAppLib/QuasarApp.pro
#Pe.file = $$PWD/pe/pe-parser-library/pe-parser.pro
