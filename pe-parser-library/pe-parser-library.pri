#
# Copyright (C) 2018-2019 QuasarApp.
# Distributed under the lgplv3 software license, see the accompanying
# Everyone is permitted to copy and distribute verbatim copies
# of this license document, but changing it is not allowed.
#

!isEmpty(PE_LIB):error("pe-parser-library.pri already included")
PE_LIB = 1

#DEPENDS
CONFIG(release, debug|release): {
    PE_LIB_OUTPUT_DIR="$$PWD/build/release"
} else {
    PE_LIB_OUTPUT_DIR="$$PWD/build/debug"
}

LIBS += -L$$PE_LIB_OUTPUT_DIR -lpe-parser-library

INCLUDEPATH += "$$PWD/include"



