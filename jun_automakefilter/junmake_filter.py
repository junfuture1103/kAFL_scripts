# 아래 형식에 맞춰 Code의 constraints를 입력해주세요
# 파싱된 결과를 넘겨 주신다면 그냥 복붙만 하면 된답니다.
code_constraints = [ 
        {'ioctl_code':0xa3350404, 'inputBufferLength':0x10, 'symbol':'=='},
        {'ioctl_code':0xa3350408, 'inputBufferLength':0x10, 'symbol':'=='},
        {'ioctl_code':0xa335040c, 'inputBufferLength':None, 'symbol':None},
        {'ioctl_code':0xa3350410, 'inputBufferLength':None, 'symbol':None},
        {'ioctl_code':0xa3350424, 'inputBufferLength':None, 'symbol':None},
        {'ioctl_code':0xa335041c, 'inputBufferLength':0x0, 'symbol':'!='},
        {'ioctl_code':0xa3350414, 'inputBufferLength':0x0, 'symbol':'!='}, 
        {'ioctl_code':0xa335044c, 'inputBufferLength':0x4, 'symbol':'=='},
        {'ioctl_code':0xa3350418, 'inputBufferLength':None, 'symbol':None},
        {'ioctl_code':0xa3350440, 'inputBufferLength':0x618, 'symbol':'=='},
        {'ioctl_code':0xa3350448, 'inputBufferLength':0x4, 'symbol':'=='},
        {'ioctl_code':0xa3350444, 'inputBufferLength':0x4, 'symbol':'=='},
        {'ioctl_code':0xa3350450, 'inputBufferLength':0x4, 'symbol':'=='},
        {'ioctl_code':0xa3350420, 'inputBufferLength':0x4, 'symbol':'=='},        
        {'ioctl_code':0xa3350040, 'inputBufferLength':None, 'symbol':None},
        {'ioctl_code':0xa3350018, 'inputBufferLength':0x0, 'symbol':'!='},
        {'ioctl_code':0xa335004c, 'inputBufferLength':0x4, 'symbol':'=='},
        {'ioctl_code':0xa3350008, 'inputBufferLength':None, 'symbol':None},
        {'ioctl_code':0xa3350020, 'inputBufferLength':0x4, 'symbol':'=='},
        {'ioctl_code':0xa335000c, 'inputBufferLength':0x4, 'symbol':'=='},
        {'ioctl_code':0xa3350000, 'inputBufferLength':None, 'symbol':None},
        {'ioctl_code':0xa3350028, 'inputBufferLength':0x8, 'symbol':'=='},
        {'ioctl_code':0xa3350048, 'inputBufferLength':0x4, 'symbol':'=='}, 
        {'ioctl_code':0xa3350024, 'inputBufferLength':0x4, 'symbol':'=='},
        {'ioctl_code':0xa335001c, 'inputBufferLength':0x0, 'symbol':'!='},
        {'ioctl_code':0xa335002c, 'inputBufferLength':0x14, 'symbol':'=='},
        {'ioctl_code':0xa3350034, 'inputBufferLength':0x0, 'symbol':'!='},
        {'ioctl_code':0xa3350014, 'inputBufferLength':0x0, 'symbol':'!='},
        {'ioctl_code':0xa3350038, 'inputBufferLength':0x0, 'symbol':'!='},        
        {'ioctl_code':0xa3350030, 'inputBufferLength':0x0, 'symbol':None},
        {'ioctl_code':0xa3350050, 'inputBufferLength':0x0, 'symbol':'!='},
        {'ioctl_code':0xa3350004, 'inputBufferLength':None, 'symbol':None},
        {'ioctl_code':0xa3350044, 'inputBufferLength':0x1, 'symbol':'=='},
        {'ioctl_code':0xa335003c, 'inputBufferLength':0x0, 'symbol':'!='},
        {'ioctl_code':0xacd2201c, 'inputBufferLength':None, 'symbol':None},
        {'ioctl_code':0xacd22018, 'inputBufferLength':None, 'symbol':None},
        {'ioctl_code':0xacd22004, 'inputBufferLength':None, 'symbol':None}, 
        {'ioctl_code':0xacd22020, 'inputBufferLength':None, 'symbol':None},
        {'ioctl_code':0xacd22014, 'inputBufferLength':None, 'symbol':None},
        {'ioctl_code':0xacd22010, 'inputBufferLength':None, 'symbol':None},
        {'ioctl_code':0xacd22008, 'inputBufferLength':None, 'symbol':None},
        {'ioctl_code':0xacd2200c, 'inputBufferLength':None, 'symbol':None},        
        {'ioctl_code':0xacd22024, 'inputBufferLength':None, 'symbol':None}
        ]

pass_message = '\n    print(\'통과했습니다. 통과한 패이로드 : \', show)'
have_to_filtering = []
filtering_constraint_1 = 'if'
filtering_constraint_2 = 'if'
filtering_constraint_3 = 'if'
filtering_constraint_4 = 'if ('
filtering_constraint_5 = 'if ('
filtering_constraint_6 = 'if ('

# for i in range(0,len(code_constraints),1):

#     tmp = 'ioctl_codeset[ioctl_count] == ' + str(i) + ' and ioctl_data_len[ioctl_count] '

#     if code_constraints[i]['symbol'] == None:
#         print('# ' + 'ioctl_code [' + str(i) + '] has no constraints!')
#         i += 1

#     else:
#         have_to_filtering.append(i)
#         final = tmp + code_constraints[i]['symbol'] + ' ' + str(code_constraints[i]['inputBufferLength']) + ':'
    
#         if i == 0:
#             print('if ' + final + pass_message + '\n   return True')

#         else:
#             print('elif ' + final + pass_message + '\n    return True')

for i in range(0,len(code_constraints),1):

    tmp = 'decoded_buf[ioctl_count].ioctlCode == constraints[' + str(i) + '] && decoded_buf[ioctl_count].inputBufferSize '

    if code_constraints[i]['symbol'] == None:
        print('// ' + 'ioctl_code [' + str(i) + '] has no constraints!')
        i += 1

    else:
        have_to_filtering.append(i)
        final = tmp + code_constraints[i]['symbol'] + ' ' + str(code_constraints[i]['inputBufferLength'])
    
        if i == 0:
            print('if (' + final + '){\n   return ioctl_num;}')

        else:
            print('else if (' + final + '){\n    return ioctl_num;}')

#if show[k] == '0' or show[k] == '1' or show[k] == '2' or show[k] == '3' :

for l in have_to_filtering:
    if l == int(have_to_filtering[len(have_to_filtering)-1]):
        filtering_constraint_3 += ' show [0] == \'' + str(l) + '\':'    
    else:
        filtering_constraint_3 += ' show [0] == \'' + str(l) + '\' or'

for j in have_to_filtering:
    if j == int(have_to_filtering[len(have_to_filtering)-1]):
        filtering_constraint_1 += ' show [i] == \'' + str(j) + '\':'    
    else:
        filtering_constraint_1 += ' show [i] == \'' + str(j) + '\' or'

for k in have_to_filtering:
    if k == int(have_to_filtering[len(have_to_filtering)-1]):
        filtering_constraint_2 += ' show [k] == \'' + str(k) + '\':'    
    else:
        filtering_constraint_2 += ' show [k] == \'' + str(k) + '\' or'

### C언어(decoder) 용 ###
for c in have_to_filtering:
    if c == int(have_to_filtering[len(have_to_filtering)-1]):
        filtering_constraint_4 += ' data[i] == \'' + str(c) + '\''    
    else:
        filtering_constraint_4 += ' data[i] == \'' + str(c) + '\' ||'

for c2 in have_to_filtering:
    if c2 == int(have_to_filtering[len(have_to_filtering)-1]):
        filtering_constraint_5 += ' data[k] == \'' + str(c2) + '\''    
    else:
        filtering_constraint_5 += ' data[k] == \'' + str(c2) + '\' ||'

for c3 in have_to_filtering:
    if c3 == int(have_to_filtering[len(have_to_filtering)-1]):
        filtering_constraint_6 += ' data[0] == \'' + str(c3) + '\''    
    else:
        filtering_constraint_6 += ' data[0] == \'' + str(c3) + '\' ||'

print('\n해당 드라이버의 constraints의 총개수는 : ' + str(len(code_constraints)) + '입니다. \n위의 내용을 복사해서 붙여넣어주세요')

#if (data[i] == '0' || data[i] == '1' || data[i] == '2' || data[i] == '3'){

print('\n#### 이 부분을 복사해서 필터(반복문 [0]) 조건에 복붙 ####\n')
print(filtering_constraint_3 + '\n')
print('#### 이 부분을 복사해서 필터(반복문 [i]) 조건에 복붙 ####\n')
print(filtering_constraint_1 + '\n')
print('#### 이 부분을 복사해서 필터(반복문 [k]) 조건에 복붙 ####\n')
print(filtering_constraint_2 + '\n')
print('#### 이 부분을 복사해서 C언어 디코더(조건문 [0]) 조건에 복붙 ####\n')
print(filtering_constraint_6 + ')' '\n')
print('#### 이 부분을 복사해서 C언어 디코더(조건문 [i]) 조건에 복붙 ####\n')
print(filtering_constraint_4 + ')' '\n')
print('#### 이 부분을 복사해서 C언어 디코더(조건문 [k]) 조건에 복붙 ####\n')
print(filtering_constraint_5 + ')' '\n')

print('#### 이 부분을 복사해서 decoder constraints[]에 복붙 ####\n')
ioctl_count = 0
for ioctl_count in range(0,len(code_constraints),1):
    print(hex(code_constraints[ioctl_count]['ioctl_code']) + ',')

