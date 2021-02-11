//
// Created by yon on 09/02/2021.
//

#pragma once

#include "json_output.hpp"

#include <assertUtils.hpp>
#include "hex_tools.h"
#include "categorization/kv_blockchain.h"
#include <algorithm>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#if __has_include(<filesystem>)
#include <filesystem>
namespace fs = std::filesystem;
#elif __has_include(<experimental/filesystem>)
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#else
#error "Missing filesystem support"
#endif
namespace concord::kvbc::tools::kv_blockchain_editor {
struct BlockVisitor {
  const std::map<std::string, std::string> operator()(const concord::kvbc::categorization::BlockMerkleInput& updates) {
    return updates.kv;
  }
  const std::map<std::string, std::string> operator()(const concord::kvbc::categorization::VersionedInput& updates) {
    std::map<std::string, std::string> ret;
    for (auto& update : updates.kv) {
      ret.emplace(update.first, update.second.data);
    }
    return ret;
  }
  const std::map<std::string, std::string> operator()(const concord::kvbc::categorization::ImmutableInput& updates) {
    std::map<std::string, std::string> ret;
    for (auto& update : updates.kv) {
      ret.emplace(update.first, update.second.data);
    }
    return ret;
  }
};

struct ValueVisitor {
  std::tuple<BlockId, std::string> operator()(const concord::kvbc::categorization::MerkleValue& val) {
    return std::make_tuple(val.block_id, val.data);
  }
  std::tuple<BlockId, std::string> operator()(const concord::kvbc::categorization::VersionedValue& val) {
    return std::make_tuple(val.block_id, val.data);
  }
  std::tuple<BlockId, std::string> operator()(const concord::kvbc::categorization::ImmutableValue& val) {
    return std::make_tuple(val.block_id, val.data);
  }
};

using namespace std::string_literals;
using concordUtils::toJson;

inline const auto kToolName = "kv_blockchain_editor"s;

template <typename Tag>
struct Arguments {
  std::vector<std::string> values;
};

struct CommandLineArgumentsTag {};
struct CommandArgumentsTag {};

using CommandArguments = Arguments<CommandArgumentsTag>;
using CommandLineArguments = Arguments<CommandArgumentsTag>;

std::shared_ptr<concord::storage::rocksdb::NativeClient> native_client;
std::unique_ptr<concord::kvbc::categorization::KeyValueBlockchain> bc_;

void init_bc(const std::string& rocksdb_path) {
  native_client = concord::storage::rocksdb::NativeClient::newClient(
      rocksdb_path, true, ::concord::storage::rocksdb::NativeClient::DefaultOptions{});
  bc_ = std::make_unique<concord::kvbc::categorization::KeyValueBlockchain>(native_client, false);
}
auto toBlockId(const std::string& s) {
  if (s.find_first_not_of("0123456789") != std::string::npos) {
    throw std::invalid_argument{"Invalid BLOCK-ID: " + s};
  }
  return kvbc::BlockId{std::stoull(s, nullptr)};
}

struct GetGenesisBlockID {
  bool read_only = true;
  std::string description() const {
    return "getGenesisBlockID\n"
           "  Returns the genesis block ID.";
  }
  std::string execute(const concord::kvbc::categorization::KeyValueBlockchain& bc, const CommandArguments&) const {
    return toJson("genesisBlockID", bc.getGenesisBlockId());
  }
};

struct GetLastBlockID {
  bool read_only = true;
  std::string description() const {
    return "getLastBlockID\n"
           " Returns the last block ID";
  }

  std::string execute(const concord::kvbc::categorization::KeyValueBlockchain& bc, const CommandArguments&) const {
    return toJson("lastBlockID", bc.getLastReachableBlockId());
  }
};

struct GetRawBlock {
  bool read_only = true;
  std::string description() const {
    return "getRawBlock BLOCK-ID\n"
           "  Returns a serialized raw block (encoded in hex).";
  }

  std::string execute(const concord::kvbc::categorization::KeyValueBlockchain& bc, const CommandArguments& args) const {
    if (args.values.empty()) {
      throw std::invalid_argument{"Missing BLOCK-ID argument"};
    }
    const auto raw_block = bc.getRawBlock(toBlockId(args.values.front()));
    auto raw_block_data = concord::kvbc::categorization::RawBlock::serialize(raw_block.value());
    return toJson("rawBlock", concordUtils::bufferToHex(raw_block_data.data(), raw_block_data.size()));
  }
};

struct GetRawBlockRange {
  bool read_only = true;
  std::string description() const {
    return "getRawBlockRange BLOCK-ID-START BLOCK-ID-END\n"
           "  Returns a list of serialized raw blocks (encoded in hex) in the [BLOCK-ID-START, BLOCK-ID-END) range.";
  }

  std::string execute(const concord::kvbc::categorization::KeyValueBlockchain& bc, const CommandArguments& args) const {
    if (args.values.size() < 2) {
      throw std::invalid_argument{"Missing or invalid block range"};
    }
    const auto end = toBlockId(args.values[1]);
    if (end == 0) {
      throw std::invalid_argument{"Invalid BLOCK-ID-END value"};
    }
    const auto first = toBlockId(args.values[0]);
    const auto last = std::min(end - 1, bc.getLastReachableBlockId());
    if (first > last) {
      throw std::invalid_argument{"Invalid block range"};
    }
    auto raw_blocks = std::vector<std::pair<std::string, std::string>>{};
    for (auto i = first; i <= last; ++i) {
      const auto raw_block = bc.getRawBlock(i);
      auto raw_block_data = concord::kvbc::categorization::RawBlock::serialize(raw_block.value());
      raw_blocks.emplace_back("rawBlock" + std::to_string(i),
                              concordUtils::bufferToHex(raw_block_data.data(), raw_block_data.size()));
    }
    return toJson(raw_blocks);
  }
};

struct GetBlockInfo {
  bool read_only = true;
  std::string description() const {
    return "getBlockInfo BLOCK-ID\n"
           "  Returns information about the requested block (excluding its key-values).";
  }

  std::string execute(const concord::kvbc::categorization::KeyValueBlockchain& bc, const CommandArguments& args) const {
    if (args.values.empty()) {
      throw std::invalid_argument{"Missing BLOCK-ID argument"};
    }
    const auto raw_block = bc.getRawBlock(toBlockId(args.values.front()));
    std::string categories_info = "[";
    for (auto& [cat_id, _] : raw_block.value().data.updates.kv) {
      categories_info += "\"" + cat_id + "\",";
    }
    categories_info[categories_info.size() - 1] = ']';
    const auto state_hash = raw_block.value().data.category_root_hash;
    const auto parent_digest = raw_block.value().data.parent_digest;
    const auto key_values = raw_block.value().data.updates.kv;
    std::map<std::string, std::string> json;
    for (auto& it : state_hash) {
      json.emplace("rootHash_" + it.first, concordUtils::bufferToHex(it.second->data(), it.second->size()));
    }
    json.emplace("parentBlockDigest", concordUtils::bufferToHex(parent_digest.data(), parent_digest.size()));
    json.emplace("keyValueCount", std::to_string(key_values.size()));
    json.emplace("categorizes", categories_info);
    return toJson(json);
  }
};

struct GetBlockKeyValues {
  std::string description() const {
    return "getBlockKeyValues BLOCK-ID\n"
           "  Returns the block's key-values.";
  }

  std::string execute(const concord::kvbc::categorization::KeyValueBlockchain& bc, const CommandArguments& args) const {
    if (args.values.empty()) {
      throw std::invalid_argument{"Missing BLOCK-ID"};
    }
    std::list<std::string> categorizes;
    auto raw_block = bc.getRawBlock(toBlockId(args.values.front()));
    for (auto& [cat, _] : raw_block.value().data.updates.kv) {
      categorizes.push_front(cat);
    }
    std::map<std::string, std::string> updates;
    auto block_updates = bc.getBlockUpdates(toBlockId(args.values.front()));
    for (auto& cat : categorizes) {
      auto cat_updates = block_updates.value().categoryUpdates(cat).value().get();
      auto updates_map = std::visit(BlockVisitor(), cat_updates);
      std::map<std::string, std::string> hex_map;
      for (auto& [key, val] : updates_map) {
        hex_map.emplace(concordUtils::bufferToHex(key.data(), key.size()),
                        concordUtils::bufferToHex(val.data(), val.size()));
      }
      updates.emplace(cat, toJson(hex_map));
    }
    return toJson(updates);
  }
};

struct GetValue {
  std::string description() const {
    return "getValue HEX-KEY CATEGORY-ID [BLOCK-VERSION]\n"
           "  Gets a value by a hex-encoded key and (optionally) a block version.\n"
           "  If no BLOCK-VERSION is passed, the value for the latest one will be returned\n"
           "  (if existing). If the key doesn't exist at BLOCK-VERSION, but exists at an\n"
           "  earlier version, its value at the earlier version will be returned.";
  }

  std::string execute(const concord::kvbc::categorization::KeyValueBlockchain& bc, const CommandArguments& args) const {
    if (args.values.size() < 2) {
      throw std::invalid_argument{"Missing HEX-KEY argument or CATEGORY-ID argument"};
    }
    const auto key = concordUtils::hexToString(args.values.front());
    const auto cat_id = args.values[1];
    auto requested_block_version = bc.getLastReachableBlockId();
    if (args.values.size() > 2) {
      requested_block_version = toBlockId(args.values[2]);
    }
    const auto val = std::visit(ValueVisitor(), bc.get(cat_id, key, requested_block_version).value());
    return toJson(std::map<std::string, std::string>{
        std::make_pair("blockVersion", std::to_string(std::get<0>(val))),
        std::make_pair("value", concordUtils::bufferToHex(std::get<1>(val).data(), std::get<1>(val).size()))});
  }
};

struct GetCategoryValues {
  std::string description() const {
    return "GetCategoryValues CATEGORY-ID [BLOCK-VERSION]\n"
           "  Gets a value by category id and (optionally) a block version.\n"
           "  If no BLOCK-VERSION is passed, the value for the latest one will be returned\n"
           "  (if existing). If the key doesn't exist at BLOCK-VERSION, but exists at an\n"
           "  earlier version, its value at the earlier version will be returned.";
  }

  std::string execute(const concord::kvbc::categorization::KeyValueBlockchain& bc, const CommandArguments& args) const {
    if (args.values.empty()) {
      throw std::invalid_argument{"Missing CATEGORY-ID argument"};
    }
    const auto cat_id = args.values.front();
    auto requested_block_version = bc.getLastReachableBlockId();
    if (args.values.size() > 1) {
      requested_block_version = toBlockId(args.values[1]);
    }
    const auto updates = bc.getBlockUpdates(requested_block_version).value().categoryUpdates(cat_id).value().get();
    auto updates_map = std::visit(BlockVisitor(), updates);
    std::map<std::string, std::string> hex_map;
    for (auto& [key, val] : updates_map) {
      hex_map.emplace(concordUtils::bufferToHex(key.data(), key.size()),
                      concordUtils::bufferToHex(val.data(), val.size()));
    }
    return toJson(hex_map);
  }
};

using Command = std::variant<GetGenesisBlockID,
                             GetLastBlockID,
                             GetRawBlock,
                             GetRawBlockRange,
                             GetBlockInfo,
                             GetBlockKeyValues,
                             GetValue,
                             GetCategoryValues>;
inline const auto commands_map = std::map<std::string, Command>{
    std::make_pair("getGenesisBlockID", GetGenesisBlockID{}),
    std::make_pair("getLastBlockID", GetLastBlockID{}),
    std::make_pair("getRawBlock", GetRawBlock{}),
    std::make_pair("getRawBlockRange", GetRawBlockRange{}),
    std::make_pair("getBlockInfo", GetBlockInfo{}),
    std::make_pair("getBlockKeyValues", GetBlockKeyValues{}),
    std::make_pair("getValue", GetValue{}),
    std::make_pair("GetCategoryValues", GetCategoryValues{}),
};

inline std::string usage() {
  auto ret = "Usage: " + kToolName + " PATH-TO-DB COMMAND [ARGUMENTS]...\n\n";
  ret += "Supported commands:\n\n";

  for (const auto& kv : commands_map) {
    ret += std::visit([](const auto& command) { return command.description(); }, kv.second);
    ret += "\n\n";
  }

  ret += "Note:\n";
  ret += "The DB Editor is configured to use the following non-provable keys:\n";
  ret += "0x20, 0x22\n\n";

  ret += "Examples:\n";
  ret += "  " + kToolName + " /rocksdb-path getGenesisBlockID\n";
  ret += "  " + kToolName + " /rocksdb-path getRawBlock 42\n";
  ret += "  " + kToolName + " /rocksdb-path getValue 0x0a0b0c\n";
  ret += "  " + kToolName + " /rocksdb-path getValue 0x0a0b0c 42\n";

  return ret;
}

inline constexpr auto kMinCmdLineArguments = 3ull;

inline CommandLineArguments command_line_arguments(int argc, char* argv[]) {
  auto cmd_line_args = CommandLineArguments{};
  for (auto i = 0; i < argc; ++i) {
    cmd_line_args.values.push_back(argv[i]);
  }
  return cmd_line_args;
}

inline CommandArguments command_arguments(const CommandLineArguments& cmd_line_args) {
  auto cmd_args = CommandArguments{};
  for (auto i = kMinCmdLineArguments; i < cmd_line_args.values.size(); ++i) {
    cmd_args.values.push_back(cmd_line_args.values[i]);
  }
  return cmd_args;
}

inline int run(const CommandLineArguments& cmd_line_args, std::ostream& out, std::ostream& err) {
  if (cmd_line_args.values.size() < kMinCmdLineArguments) {
    err << usage();
    return EXIT_FAILURE;
  }

  auto cmd_it = commands_map.find(cmd_line_args.values[2]);
  if (cmd_it == std::cend(commands_map)) {
    err << usage();
    return EXIT_FAILURE;
  }

  try {
    init_bc(cmd_line_args.values[1]);
    const auto output = std::visit(
        [&](const auto& command) -> std::string { return command.execute(*bc_, command_arguments(cmd_line_args)); },
        cmd_it->second);
    out << output << std::endl;
  } catch (const std::exception& e) {
    err << "Failed to execute command [" << cmd_it->first << "], reason: " << e.what() << std::endl;
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

}  // namespace concord::kvbc::tools::kv_blockchain_editor
