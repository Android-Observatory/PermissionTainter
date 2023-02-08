# APK Taint Analysis

Note: for now the script is looking for methods that use a string containing
`logcat` in them as a starting point. We will need to interface this with
`permissionTracer` at some point.

### TODO

  - support inter-components communication
    - intent detection done, needs more exhaustive testing (maybe create an app
      with all possible constructors and methods to make sure everything works)
    - need to expand tree
  - support extras (key, value)

## Flow Analysis On-Demand

For the analysis of custom permissions we apply different flow analysis to get
possible data leakages or misuses of them through the different components of
the applications.

Our flow analysis is divided into different steps that at the end will give us
a structure useful for the analysis, main focus will be on: *data flow
analysis* and *taint analysis*.

### Call Flow Graph

Part of our analysis involve doing a call flow graph to know possible flows
from one method from one component to others. The algorithm uses a set of
predefined sinks and sources to bound the call flow graph, sinks are used as
starting point for the graph, then following a bottom-up approach a tree is
created following cross-references, the algorithm will finish once no more
cross-references are found, or when one of the sources is found in the way.
This will give us a tree, from which we will choose only the paths from sources
to sinks.

![Call Flow Graph Tree](/images/CallFlowGraphTree.png)
![Call Flow Graph Existing Paths](/images/CallFlowGraphPaths.png)

Found paths will be used in later analysis for creating the control flow and
data flow graphs, and we use them to apply the taint analysis too.

#### Handling indirect calls

Due to the asynchronous mechanisms used in Android, it's possible that within
the app, one component can call other one without using a **call** instruction,
if the target component can handle an intent action, any other component can
make use of it throwing that intent action.

While this could be a corner case in many other operating system, it is a well
known *IPC* mechanism in Android, and for that reason is important to handle
possible calls. Intents can be declared in the ''AndroidManifest.xml'' file, but
also can be registered dynamically in runtime.

For the moment, the analysis parses the ''AndroidManifest.xml'' file and
extract the components together with handled intents, finally analyzing the
intent calls from the code. If it exists any internal call to an intent with an
action handled by other internal component, a cross reference is created to
have a more complete call flow graph.

![Call Flow Graph Intent](/images/IntentGraph.png)

#### Handling possible error cases

During the construction of the call flow graph some cases can make the
construction algorithm fail, or enter in an infinite loop. One simple example
of this is recursion, where a method call itself until a specific state happens
(e.g., a counter reach 0). This code is translated as a cross-reference to and
from the same method.

For these cases, different heuristics must be applied to avoid walking the same
path in an infinite loop, heuristics must detect these cases, create an edge
from a method to itself (in case of recursion), or in case of calls between
different methods, create a loop edge and avoid going through that path again.
