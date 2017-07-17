dump_prog = executable(
		'dump-prog',
		'dump.cpp',
		include_directories : [ incdirs ],
		install : true,
		install_dir : join_paths(get_option('datadir'), 'pe-parse/examples'),
		link_with : pe_parser_library)
