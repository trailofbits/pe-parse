#ifndef _NT_HEADERS
#define _NT_HEADERS
#include <boost/cstdint.hpp>

struct dos_header {
    boost::uint16_t   e_magic;           
    boost::uint16_t   e_cblp;            
    boost::uint16_t   e_cp;              
    boost::uint16_t   e_crlc;            
    boost::uint16_t   e_cparhdr;         
    boost::uint16_t   e_minalloc;        
    boost::uint16_t   e_maxalloc;        
    boost::uint16_t   e_ss;              
    boost::uint16_t   e_sp;              
    boost::uint16_t   e_csum;            
    boost::uint16_t   e_ip;              
    boost::uint16_t   e_cs;              
    boost::uint16_t   e_lfarlc; 
    boost::uint16_t   e_ovno;            
    boost::uint16_t   e_res[4];          
    boost::uint16_t   e_oemid;           
    boost::uint16_t   e_oeminfo; 
    boost::uint16_t   e_res2[10];        
    boost::uint32_t   e_lfanew;          
};

#endif
