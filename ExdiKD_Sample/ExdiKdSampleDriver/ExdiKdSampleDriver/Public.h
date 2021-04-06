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
// Define an Interface Guid so that app can find the device and talk to it.
//

DEFINE_GUID (GUID_DEVINTERFACE_ExdiKdSampleDriver,
    0xeb5d25a4,0xdd48,0x42d3,0x9e,0x09,0x3d,0xdf,0xac,0x67,0xc6,0x4a);
// {eb5d25a4-dd48-42d3-9e09-3ddfac67c64a}
