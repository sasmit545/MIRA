                    STATIC MCP SERVER
                           │
       ┌───────────────────┼───────────────────┐
       │                   │                   │
    INTAKE              STRUCTURE           CONTENT
       │                   │                   │
   file_info          analyze_pe          strings
   file_type          sections            resources
   hashes             imports
                       exports
                       headers
       │                   │                   │
       └───────────────────┼───────────────────┘
                           │
                           ▼
                    CODE ANALYSIS
                           │
                 ┌─────────┼─────────┐
                 │         │         │
             disassembly  CAPA     YARA
                 │
                 ▼
             SEMANTIC /
             BEHAVIORAL
                 │
          ┌──────┼──────┐
          │      │      │
       API map  CFG   functions
          │
          ▼
        OBFUSCATION
          │
       ┌──┼───────────┐
       │  │           │
     entropy packer  encoding