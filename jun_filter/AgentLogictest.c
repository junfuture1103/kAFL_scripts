/*
This is the Prototype(2) of bruteforce-fuzztesting automation code.
Designed for medcored.sys.
*/
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "kafl_user.h"
#define IOCTL_KAFL_INPUT    (ULONG) CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL2_KAFL_INPUT    (ULONG) CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_NEITHER, FILE_ANY_ACCESS)
#define PAYLOAD_SIZE						(128 << 10)	

typedef enum {false, true} bool;

typedef struct _kAFL_IRP {
    DWORD ioctlCode;
    int32_t inputBufferSize;
    int32_t outputBufferSize;
    uint8_t* payload;
} kAFL_IRP;

typedef struct{
	int32_t size;
	uint8_t data[PAYLOAD_SIZE-sizeof(int32_t)-sizeof(uint8_t)];
} kAFL_payload;

DWORD constraints[10] = {
    IOCTL_KAFL_INPUT,
    IOCTL2_KAFL_INPUT
};

// decode_buf(==kAFL_decoded)는 ioctl code갯수만큼 있다. 각각의 버퍼에 분류한 ioctl-data 값 넣어주기 (decoder)
// data와 size는 fuzzer에서 받은 전체 패이로드 data랑 패이로드 size랍니다. 무조건 그걸 받아와요.
int32_t payload_decode(uint8_t* data, int32_t size, kAFL_IRP decoded_buf[]) 
{
    int32_t cIndex;
    int32_t ioctl_num = 0; // ioctl_num == decoded_len
    int last_index = size-1;
    int i = 0;
    //fuzzer한테 받아온 데이터 끝까지
    if ( data[0] == '0' || data[0] == '1'){
        while (i < size) {
            if ( data[i] == '0' || data[i] == '1'){
                cIndex = data[i] - '0';
                //0,1,2...값에서 진짜 ioctl 코드로 담아주기
                decoded_buf[ioctl_num].ioctlCode = constraints[cIndex];

                if (i == last_index){
                    decoded_buf[ioctl_num].inputBufferSize = 0 ;
                    decoded_buf[ioctl_num].payload = NULL;
                    return ioctl_num;
                }
                else{
                    //다음 ioctl code 찾기!
                    int k = i+1;
                    while (k < size){
                        if (k == last_index){
                            if ( data[k] == '0' || data[k] == '1'){
                                decoded_buf[ioctl_num].inputBufferSize = k-i-1;
                                if (i+1 == k){
                                    decoded_buf[ioctl_num].payload = NULL;
                                    break;
                                }
                                else{
                                    decoded_buf[ioctl_num].payload = &data[++i];
                                    break;
                                }
                            }

                            else{
                                decoded_buf[ioctl_num].inputBufferSize = k-i;
                                decoded_buf[ioctl_num].payload = &data[++i];
                                break;
                            }
                        }

                        else{
                            if ( data[k] == '0' || data[k] == '1'){
                                decoded_buf[ioctl_num].inputBufferSize = k-i-1;
                                if (i+1 == k){
                                    decoded_buf[ioctl_num].payload = NULL;
                                    break;}
                                else{
                                    decoded_buf[ioctl_num].payload = &data[++i];
                                    break;
                                }
                            }
                        }
                        k++;
                    }
                }

                //decoded_buf[ioctl_num].outputBufferSize = constraints[cIndex];
                i += decoded_buf[ioctl_num].inputBufferSize + 1;
                ioctl_num++;
            }else{
                i++;
            }
        }

    //     int ioctl_count = 0;
    //     while (ioctl_count < ioctl_num){
    //             if (decoded_buf[ioctl_count].ioctlCode == constraints[0] && decoded_buf[ioctl_count].inputBufferSize == 16){
    //                 return ioctl_num;}
    //             else if (decoded_buf[ioctl_count].ioctlCode == constraints[1] && decoded_buf[ioctl_count].inputBufferSize == 16){
    //                 return ioctl_num;}
    //             else{
    //                 return -1;
    //             }
    //             ioctl_count++;
    //         }
    // }
    }else{
        return -1;
    }
    return -1;
}



int main(int argc, char** argv)
{
    kAFL_IRP decoded_buf[0x20];

    // uint8_t* outBuffer = NULL;

    hprintf("Starting... %s\n", argv[0]);
    
    kAFL_payload* payload_buffer = (kAFL_payload*)VirtualAlloc(0, PAYLOAD_SIZE, MEM_COMMIT, PAGE_READWRITE);
    
    memset(payload_buffer, 0xff, PAYLOAD_SIZE);

    payload_buffer->data

    /* open vulnerable driver */
    HANDLE kafl_vuln_handle = NULL;
    kafl_vuln_handle = CreateFile((LPCSTR)"\\\\.\\medcored",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
        NULL
    );

    if (kafl_vuln_handle == INVALID_HANDLE_VALUE) {
        hprintf("cannot get device handle: 0x%x\n", GetLastError());
        ExitProcess(0);
    }



    while (1) {

        int32_t ioctl_num = payload_decode(payload_buffer->data, payload_buffer->size, decoded_buf);
        hprintf("Show me the ioctl_num : %ld", ioctl_num);

        if (ioctl_num != -1){
            // payload_buffer->data는 fuzzer에서 넘어온 전체 패이로드, payload_buffer->size는 fuzzer에서 넘어온 패이로드의 전체길이
            // hprintf("Here is decodedbuf %s, %ld\n", payload_buffer->data, payload_buffer->size);
            hprintf("Congraturation! you can pass this filter! payload : %s inputbuffersize : %ld \n", payload_buffer->data, payload_buffer->size);    


            for (int j = 0; j < ioctl_num; j++) {
                /* kernel fuzzing */
                DeviceIoControl(kafl_vuln_handle,
                    (DWORD)decoded_buf[j].ioctlCode,
                    (LPVOID)decoded_buf[j].payload,
                    (DWORD)decoded_buf[j].inputBufferSize,
                    NULL,
                    0,
                    NULL,
                    NULL
                );
            }
            /* inform fuzzer about finished fuzzing iteration */
            // hprintf("Injection finished.\n");
            
        }
    }

    return 0;
}