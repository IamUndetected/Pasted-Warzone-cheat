// dllmain.cpp : Definisce il punto di ingresso per l'applicazione DLL.
#include "pch.h"
#include "Classes.h"
#include "Offsets.h"
#include "Memory.h"
#include <psapi.h>
#include <process.h>

#define RVA(addr, size) ((uintptr_t)((UINT_PTR)(addr) + *(PINT)((UINT_PTR)(addr) + ((size) - sizeof(INT))) + (size)))

#define INRANGE(x,a,b)	(x >= a && x <= b) 
#define getBits( x )	(INRANGE((x&(~0x20)),'A','F') ? ((x&(~0x20)) - 'A' + 0xa) : (INRANGE(x,'0','9') ? x - '0' : 0))
#define getByte( x )	(getBits(x[0]) << 4 | getBits(x[1]))

#define OFFSET_CHARACTERINFO_RECOIL 0x19B48 //0F 85 ? ? ? ? 0F 2E 80 ? ? ? ? 0F 85 ? ? ? ? 4C 8D 96 ? ? ? ?

#define QWORD unsigned __int64

Offsets* offsets = nullptr;

uintptr_t   moduleBase = 0;
uintptr_t           cg = 0;
bool              bUav = false;
int             health = 0;
int             GameMode = 0;
bool noRecoil = false;

// 48 8b 04 c1 48 8b 1c 03 48 8b cb 48 8b 03 ff 90 98 00 00 00
uint64_t DecryptClientInfo(uint64_t baseModuleAddr, uint64_t peb)
{

	uint64_t rax = baseModuleAddr, rbx = baseModuleAddr, rcx = baseModuleAddr, rdx = baseModuleAddr, rdi = baseModuleAddr, rsi = baseModuleAddr, r8 = baseModuleAddr, r9 = baseModuleAddr, r10 = baseModuleAddr, r11 = baseModuleAddr, r12 = baseModuleAddr, r13 = baseModuleAddr, r14 = baseModuleAddr, r15 = baseModuleAddr;
	rbx = *(uintptr_t*)(baseModuleAddr + 0x1F22D908);
	if (!rbx)
		return rbx;
	rcx = ~peb;              //mov rcx, gs:[rax]
	rax = 0x1AA4000CDF200E7;                //mov rax, 0x1AA4000CDF200E7
	rbx *= rax;             //imul rbx, rax
	rcx = ~rcx;             //not rcx
	rax = rbx;              //mov rax, rbx
	rax >>= 0xB;            //shr rax, 0x0B
	rbx ^= rax;             //xor rbx, rax
	rax = rbx;              //mov rax, rbx
	rax >>= 0x16;           //shr rax, 0x16
	rbx ^= rax;             //xor rbx, rax
	rax = baseModuleAddr + 0xFE73;          //lea rax, [0xFFFFFFFFFD781C55]
	rax = ~rax;             //not rax
	rcx *= rax;             //imul rcx, rax
	rax = rbx;              //mov rax, rbx
	rax >>= 0x2C;           //shr rax, 0x2C
	rcx ^= rax;             //xor rcx, rax
	rbx ^= rcx;             //xor rbx, rcx
	rax = rbx;              //mov rax, rbx
	rax >>= 0xE;            //shr rax, 0x0E
	rbx ^= rax;             //xor rbx, rax
	rax = rbx;              //mov rax, rbx
	rax >>= 0x1C;           //shr rax, 0x1C
	rbx ^= rax;             //xor rbx, rax
	rax = rbx;              //mov rax, rbx
	rax >>= 0x38;           //shr rax, 0x38
	rbx ^= rax;             //xor rbx, rax
	rax = rbx;              //mov rax, rbx
	r8 = 0;                 //and r8, 0xFFFFFFFFC0000000
	rax >>= 0x27;           //shr rax, 0x27
	r8 = _rotl64(r8, 0x10);                 //rol r8, 0x10
	rbx ^= rax;             //xor rbx, rax
	r8 ^= *(uintptr_t*)(baseModuleAddr + 0x78E1103);              //xor r8, [0x0000000005052E8D]
	r8 = ~r8;               //not r8
	rbx *= *(uintptr_t*)(r8 + 0x11);              //imul rbx, [r8+0x11]
	return rbx;
}
    
void NoRecoil()
{
    auto not_peb = __readgsqword(0x60);
    uint64_t characterInfo_ptr = DecryptClientInfo(moduleBase, not_peb);
    if (characterInfo_ptr)
    {
        // up, down
        QWORD r12 = characterInfo_ptr;
        r12 += OFFSET_CHARACTERINFO_RECOIL;
        QWORD rsi = r12 + 0x4;
        DWORD edx = *(QWORD*)(r12 + 0xC);
        DWORD ecx = (DWORD)r12;
        ecx ^= edx;
        DWORD eax = (DWORD)((QWORD)ecx + 0x2);
        eax *= ecx;
        ecx = (DWORD)rsi;
        ecx ^= edx;
        DWORD udZero = eax;
        //left, right
        eax = (DWORD)((QWORD)ecx + 0x2);
        eax *= ecx;
        DWORD lrZero = eax;
        *(DWORD*)(r12) = udZero;
        *(DWORD*)(rsi) = lrZero;
    }
}

bool Updated()
{
    BYTE m_checkUpdate[2] = { 0x74, 0x1D };

    for (int count{ 0 }; count < 2; ++count)
    {
        if (((BYTE*)(moduleBase + offsets->GetOffset(Offsets::CHECKUPDATE)))[count] == m_checkUpdate[count])
            return true;
    }

    return false;
}

ULONG WINAPI Init()
{
    while (moduleBase == 0)
    {
        moduleBase = (uintptr_t)GetModuleHandle(NULL);
        Sleep(30);
    }

    offsets = new Offsets();

    //if (!Updated())
    //    return NULL;

    while (!KEY_MODULE_EJECT)
    {
        cg = (uintptr_t)(moduleBase + offsets->GetOffset(Offsets::CG_T));
        GameMode = *(int*)(moduleBase + offsets->GetOffset(Offsets::GAMEMODE));

        if (KEY_UAV_MANAGER)
        {
            bUav = !bUav;
        }

        if (KEY_RECOIL_MANAGER)
        {
            noRecoil = !noRecoil;
        }
            

        if (bUav)
        {
            if (GameMode > 1)
            {
                if (cg != 0)
                {
                    health = *(int*)((uintptr_t)offsets->FindDMAAddy(cg, { 0x25C }));
                    if (health >= 0 && health <= 300)
                    {
                        *(int*)((uintptr_t)offsets->FindDMAAddy(cg, { 0x304 })) = 33619969;
                    }
                }
            }
        }

        if (noRecoil)
        {
            if(GameMode > 1)
               NoRecoil();
        }

        Sleep(1);
    }
   
    return true;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        _beginthreadex(0, 0, (_beginthreadex_proc_type)Init, 0, 0, 0);
        break;
    }

    return TRUE;
}


