/*++

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.

Environment:

    user and kernel

--*/

//
// Define an Interface Guid so that apps can find the device and talk to it.
//

DEFINE_GUID (GUID_DEVINTERFACE_FUCKMSFT,
    0x9a6bb8db,0x1295,0x4dad,0x9f,0x4b,0xd6,0xf9,0x21,0xbd,0x01,0xa2);
// {9a6bb8db-1295-4dad-9f4b-d6f921bd01a2}
