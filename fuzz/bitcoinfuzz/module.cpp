#include "module.h"
#include "mantle_lib/mantle_lib.h"

namespace bitcoinfuzz {
namespace module {
Mantle::Mantle(void) : BaseModule("Mantle") {}

std::optional<std::string>
Mantle::script_parse(std::span<const uint8_t> buffer) const {
  auto result = mantle_script_parse(buffer.data(), buffer.size());
  if (!result)
    return std::nullopt;
  std::string s(result);
  mantle_free_string(result);
  return s;
}

std::optional<std::string>
Mantle::deserialize_block(std::span<const uint8_t> buffer) const {
  auto result = mantle_deserialize_block(buffer.data(), buffer.size());
  if (!result)
    return std::nullopt;
  std::string s(result);
  mantle_free_string(result);
  return s;
}

} // namespace module
} // namespace bitcoinfuzz
