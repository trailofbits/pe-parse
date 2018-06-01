incdirs = include_directories('.')
parser_source = [
	'buffer.cpp',
	'parse.cpp'
	]

pe_parser_library = library('pe-parser-library',
			sources : parser_source,
			install : true
			)
install_headers('parse.h', subdir : 'pe-parse')
