--: Headers ---------------------------------------------
set_project ("payloader")
set_version ("0.1.0"  )
set_xmakever("2.8.0"  )


--: Includes --------------------------------------------
includes("./xmake/rules/*.lua")


--: Configs ---------------------------------------------
add_repositories("local-repo ./xmake/")
add_moduledirs("./xmake/modules/")

set_policy("build.c++.modules"    , true )
set_policy("build.c++.modules.std", false)


--: Rules -----------------------------------------------
add_rules("vscode.compile_commands")


--: Deps ------------------------------------------------
add_requires("lbyte.stx v0.2.0", {configs = {use_modules = true}})


--: Targets ---------------------------------------------
target( "payload" )
    set_default  (false    )
    set_languages("c++23"  )
    set_kind     ("binary" )
    set_basename ("payload")

    add_rules("payload_extract")

    set_values("payload.header",  {"cxx"})
    set_values("payload.section", ".payload")
    set_values("entry"          , "payload" )

    add_files(
        "./src/payload.cpp",
        "./src/core/winstructs.cppm",
        "./src/core/utils.cppm"
    )

    add_packages("lbyte.stx")

    on_config( "actions.configure"   )
    on_run   ( "actions.run_process" )


target( "loader" )
    set_default  (true     )
    set_languages("c++23"  )
    set_kind     ("binary" )
    set_basename ("loader" )

    add_files( "./src/loader.cpp" )

    add_deps("payload")
    add_packages("lbyte.stx")

    on_config( "actions.configure"   )
    on_run   ( "actions.run_process" )

