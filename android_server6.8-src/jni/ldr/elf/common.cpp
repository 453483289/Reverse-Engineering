/*
 *      Interactive disassembler (IDA)
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *                        E-mail: ig@datarescue.com
 *      ELF binary loader.
 *      Copyright (c) 1995-2006 by Iouri Kharon.
 *                        E-mail: yjh@styx.cabel.net
 *
 *      ALL RIGHTS RESERVED.
 *
 */

//#include <idp.hpp>

#include "elfbase.h"

bool unpatched;

#ifndef _LOADER_HPP
#define loader_failure() qexit(1)
#endif

#ifndef NO_ERRSTRUCT
//--------------------------------------------------------------------------
#ifdef BUILD_LOADER
static void ask_for_exit(const char *str)
{
  if ( askyn_c(ASKBTN_YES, "HIDECANCEL\n%s. Continue?", str) <= ASKBTN_NO )
    loader_failure();
}

//-------------------------------------------------------------------------
static void ask_for_exit_once(const char *str)
{
  static qstrvec_t asked;
  if ( asked.has(str) )
    return;
  ask_for_exit(str);
  asked.push_back(str);
}
#endif // BUILD_EFD

//--------------------------------------------------------------------------
#if defined(BUILD_LOADER) || defined(EFD_COMPILE)
static void _errstruct(int line)
{
  static bool asked = false;
  if ( !asked )
  {
    if ( askyn_c(ASKBTN_YES,
                 "HIDECANCEL\n"
                 "Bad file structure or read error (line %d). Continue?", line) <= ASKBTN_NO )
    {
      loader_failure();
    }
    asked = true;
  }
}
#endif

#define errstruct() _errstruct(__LINE__)
#endif

//--------------------------------------------------------------------------
NORETURN inline void errnomem(void) { printf("nomem ELF"); }

//--------------------------------------------------------------------------
//      Functions common for EFD & DEBUGGER
//--------------------------------------------------------------------------

//--------------------------------------------------------------------------
static bool dummy_error_handler(const reader_t &, reader_t::errcode_t, ...)
{
  // ignore all errors
  return true;
}

//--------------------------------------------------------------------------
bool is_elf_file(linput_t *li)
{
  reader_t reader(li);
  reader.set_handler(dummy_error_handler);
  return reader.read_ident() && reader.read_header();
}

#define PLFM_386        0         ///< Intel 80x86
#define PLFM_Z80        1         ///< 8085, Z80
#define PLFM_I860       2         ///< Intel 860
#define PLFM_8051       3         ///< 8051
#define PLFM_TMS        4         ///< Texas Instruments TMS320C5x
#define PLFM_6502       5         ///< 6502
#define PLFM_PDP        6         ///< PDP11
#define PLFM_68K        7         ///< Motorola 680x0
#define PLFM_JAVA       8         ///< Java
#define PLFM_6800       9         ///< Motorola 68xx
#define PLFM_ST7        10        ///< SGS-Thomson ST7
#define PLFM_MC6812     11        ///< Motorola 68HC12
#define PLFM_MIPS       12        ///< MIPS
#define PLFM_ARM        13        ///< Advanced RISC Machines
#define PLFM_TMSC6      14        ///< Texas Instruments TMS320C6x
#define PLFM_PPC        15        ///< PowerPC
#define PLFM_80196      16        ///< Intel 80196
#define PLFM_Z8         17        ///< Z8
#define PLFM_SH         18        ///< Renesas (formerly Hitachi) SuperH
#define PLFM_NET        19        ///< Microsoft Visual Studio.Net
#define PLFM_AVR        20        ///< Atmel 8-bit RISC processor(s)
#define PLFM_H8         21        ///< Hitachi H8/300, H8/2000
#define PLFM_PIC        22        ///< Microchip's PIC
#define PLFM_SPARC      23        ///< SPARC
#define PLFM_ALPHA      24        ///< DEC Alpha
#define PLFM_HPPA       25        ///< Hewlett-Packard PA-RISC
#define PLFM_H8500      26        ///< Hitachi H8/500
#define PLFM_TRICORE    27        ///< Tasking Tricore
#define PLFM_DSP56K     28        ///< Motorola DSP5600x
#define PLFM_C166       29        ///< Siemens C166 family
#define PLFM_ST20       30        ///< SGS-Thomson ST20
#define PLFM_IA64       31        ///< Intel Itanium IA64
#define PLFM_I960       32        ///< Intel 960
#define PLFM_F2MC       33        ///< Fujistu F2MC-16
#define PLFM_TMS320C54  34        ///< Texas Instruments TMS320C54xx
#define PLFM_TMS320C55  35        ///< Texas Instruments TMS320C55xx
#define PLFM_TRIMEDIA   36        ///< Trimedia
#define PLFM_M32R       37        ///< Mitsubishi 32bit RISC
#define PLFM_NEC_78K0   38        ///< NEC 78K0
#define PLFM_NEC_78K0S  39        ///< NEC 78K0S
#define PLFM_M740       40        ///< Mitsubishi 8bit
#define PLFM_M7700      41        ///< Mitsubishi 16bit
#define PLFM_ST9        42        ///< ST9+
#define PLFM_FR         43        ///< Fujitsu FR Family
#define PLFM_MC6816     44        ///< Motorola 68HC16
#define PLFM_M7900      45        ///< Mitsubishi 7900
#define PLFM_TMS320C3   46        ///< Texas Instruments TMS320C3
#define PLFM_KR1878     47        ///< Angstrem KR1878
#define PLFM_AD218X     48        ///< Analog Devices ADSP 218X
#define PLFM_OAKDSP     49        ///< Atmel OAK DSP
#define PLFM_TLCS900    50        ///< Toshiba TLCS-900
#define PLFM_C39        51        ///< Rockwell C39
#define PLFM_CR16       52        ///< NSC CR16
#define PLFM_MN102L00   53        ///< Panasonic MN10200
#define PLFM_TMS320C1X  54        ///< Texas Instruments TMS320C1x
#define PLFM_NEC_V850X  55        ///< NEC V850 and V850ES/E1/E2
#define PLFM_SCR_ADPT   56        ///< Processor module adapter for processor modules written in scripting languages
#define PLFM_EBC        57        ///< EFI Bytecode
#define PLFM_MSP430     58        ///< Texas Instruments MSP430
#define PLFM_SPU        59        ///< Cell Broadband Engine Synergistic Processor Unit
#define PLFM_DALVIK     60        ///< Android Dalvik Virtual Machine
#define PLFM_65C816     61        ///< 65802/65816
#define PLFM_M16C       62        ///< Renesas M16C
#define PLFM_ARC        63        ///< Argonaut RISC Core
#define PLFM_UNSP       64        ///< SunPlus unSP
#define PLFM_TMS320C28  65        ///< Texas Instruments TMS320C28x
#define PLFM_DSP96K     66        ///< Motorola DSP96000
//--------------------------------------------------------------------------
int elf_machine_2_proc_module_id(reader_t &reader)
{
  int id = -1;
  switch ( reader.get_header().e_machine )
  {
#define CASE(E_ID, P_ID) case EM_##E_ID: id = PLFM_##P_ID; break
    CASE(ARM, ARM);
    CASE(SH, SH);
    CASE(PPC, PPC);
    CASE(PPC64, PPC);
    CASE(860, I860);
    CASE(68K, 68K);
    CASE(MIPS, MIPS);
    CASE(CISCO7200, MIPS);
    CASE(CISCO3620, MIPS);
    CASE(386, 386);
    CASE(486, 386);
    CASE(X86_64, 386);
    CASE(SPARC, SPARC);
    CASE(SPARC32PLUS, SPARC);
    CASE(SPARC64, SPARC);
    CASE(ALPHA, ALPHA);
    CASE(IA64, IA64);
    CASE(H8300, H8);
    CASE(H8300H, H8);
    CASE(H8S, H8);
    CASE(H8500, H8);
    CASE(V850, NEC_V850X);
    CASE(NECV850, NEC_V850X);
    CASE(PARISC, HPPA);
    CASE(6811, 6800);
    CASE(6812, MC6812);
    CASE(I960, I960);
    CASE(ARC, ARC);
    CASE(ARCOMPACT, ARC);
    CASE(ARC_COMPACT2, ARC);
    CASE(M32R, M32R);
    CASE(ST9, ST9);
    CASE(FR, FR);
    CASE(AVR, AVR);
    CASE(SPU, SPU);
    CASE(C166, C166);
    CASE(M16C, M16C);
    CASE(MN10200, MN102L00);
    // CASE(MN10300, MN103L00); // FIXME: Dunno what to do, here.
    // CASE(MCORE, MCORE); // FIXME: PLFM_MCORE still defined in mcore/reg.cpp
#undef CASE
  }
  return id;
}

