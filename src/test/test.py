import frida

def on_diagnostics(diag):
    print("on_diagnostics:", diag)

compiler = frida.Compiler()
compiler.on("diagnostics", on_diagnostics)
bundle = compiler.build("agent.ts")
with open("_agent.js", "w", newline="\n") as f:
    f.write(bundle)