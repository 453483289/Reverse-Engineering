#include "diskio.hpp"

/// Object that represents a register
struct regobj_t
{
  int regidx;                           ///< index into dbg->registers
  int relocate;                         ///< 0-plain num, 1-must relocate
  bytevec_t value;
  size_t size(void) const { return value.size(); }
};
/// Collection of register objects
struct regobjs_t : public qvector<regobj_t>
{
};

int32 calc_file_crc32(linput_t *li);

