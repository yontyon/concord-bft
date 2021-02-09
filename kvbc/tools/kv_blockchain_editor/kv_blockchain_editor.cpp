//
// Created by yon on 09/02/2021.
//

#include "kv_blockchain_editor.hpp"
using namespace concord::kvbc::tools::kv_blockchain_editor;
int main(int argc, char *argv[]) { return run(command_line_arguments(argc, argv), std::cout, std::cerr); }

