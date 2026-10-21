#include <bitcoinfuzz/basemodule.h>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace bitcoinfuzz {
namespace module {
class Mantle : public BaseModule {
public:
  Mantle(void);
  std::optional<std::string>
  script_parse(std::span<const uint8_t> buffer) const override;
  std::optional<std::string>
  deserialize_block(std::span<const uint8_t> buffer) const override;
  ~Mantle() noexcept override = default;
};

} // namespace module
} // namespace bitcoinfuzz
