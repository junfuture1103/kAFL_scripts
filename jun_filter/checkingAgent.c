//CheckingAgent.c
/*
Copyright (C) 2017 Robert Gawlik
This file is part of kAFL Fuzzer (kAFL).
QEMU-PT is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.
QEMU-PT is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with QEMU-PT.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <windows.h>
#include <stdio.h>
#include "kafl_user.h"

#define IOCTL_CRASH_INPUT    (ULONG) CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_CONSTRAINT_INPUT    (ULONG) CTL_CODE(FILE_DEVICE_UNKNOWN, 0x950, METHOD_NEITHER, FILE_ANY_ACCESS)

char data[9] = { 1,2,3,4,5,6,7,8,9 };
DWORD size = 9;
ULONG IOCTL_CODE = 0;

int main(int argc, char** argv)
{
    /* open vulnerable driver */
    HANDLE driver_handle = NULL;
		
    if (data[2] == 2){
        IOCTL_CODE = IOCTL_CONSTRAINT_INPUT;
    }
    else{
        IOCTL_CODE = IOCTL_CRASH_INPUT;
    }

    driver_handle = CreateFile((LPCSTR)"\\\\.\\junToy",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
        NULL
    );

    if (driver_handle == INVALID_HANDLE_VALUE) {
        ExitProcess(0);
    }
    
    printf("IOCTL CODE : %ld / CRASH : %ld / CONSTRAINT : %ld", IOCTL_CODE, IOCTL_CRASH_INPUT, IOCTL_CONSTRAINT_INPUT);
    /* kernel fuzzing */
    DeviceIoControl(driver_handle,
        IOCTL_CODE,
        (LPVOID)(data),
        (DWORD)size,
        NULL,
        0,
        NULL,
        NULL
    );
    return 0;
}