# binja_moonanalyzer

binja: analyze things on the moon

## overview

- the idea of this project is to enable ai-assisted binary analysis in a chat-like fashion.
- unlike many ai-assisted analysis tools, **moonanalyzer** is designed for chat rather than api calls. this tool is for conversational, stateful binary analysis in a way that's closer to the human workflow.
- you, the user, are in the front seat, and can locate interesting code; when you find some, you can use the quick analyze tool to generate a contextualized prompt to send to the moon (your llm chat) for analysis.
- the llm sends back a dsl script that can rename things and add comments based on its analysis of the decompilation.
- it's designed in the way that you can keep adding to a stateful chat in a back-and-forth, gradually analyzing the binary.

## features

- smart analyze: send snippets of HLIL and disassembly and get back DSL that can rename and retype things
- smart patch: send snippets of HLIL and disassembly along with an objective and get back a patch

## guide

- ensure python dependency `lark` (for parsing) is installed
- go to settings, set scope to project/resource, and set project context under **MoonAnalyzer**
- navigate to a function, and use Plugins > MoonAnalyzer and an analyze command
- paste the prompt into a llm chat interface
- use Plugins > MoonAnalyzer > Execute BN-DSL and run the llm output
