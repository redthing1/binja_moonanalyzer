# binja_moonanalyzer

binja: analyze things on the moon

## overview

- the idea of this project is to enable ai-assisted binary analysis in a chat-like fashion.
- you, the user, are in the front seat, and can locate interesting code; when you find some, you can use the quick analyze tool to generate a contextualized prompt to send to the moon (your llm chat) for analysis.
- the llm sends back a dsl script that can rename things and add comments based on its analysis of the decompilation.
- it's designed in the way that you can keep adding to a stateful chat in a back-and-forth, gradually analyzing the binary.
