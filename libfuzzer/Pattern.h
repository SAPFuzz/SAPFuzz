#include "ContractABI.h"

namespace fuzzer
{
using EventType = string;
const EventType READ = "Read";
const EventType WRITE = "Write";

struct ReadWriteNode
{
    /* data */
    long GID;
    uint32_t selector;  //
    EventType type;         // READ or WRITE
    string var;               // var identifier
    ReadWriteNode(uint32_t selector, EventType type, string var)
      : GID(0), selector(selector), type(type), var(var){};
    ReadWriteNode(u256 GID, uint32_t selector, EventType type, string var)
      : GID(GID), selector(selector), type(type), var(var){};
};

enum PatternType
{
    RW,
    WR,
    WW,
    RWR,
    WWR,
    WRW,
    RWW,
    WWW,
    W1XW2XW2YW1Y,
    W1XW2YW2XW1Y,
    W1XW2YW1YW2X,
    W1XR2XR2YW1Y,
    W1XR2YR2XW1Y,
    R1XW2XW2YR1Y,
    R1XW2YW2XR1Y,
    R1XW2YR1YW2X,
    W1XR2YW1YR2X,
    ILLEGAL
};

struct Pattern
{
    vector<ReadWriteNode> nodes;
    PatternType patternType;
    Pattern(vector<ReadWriteNode> nodes) : nodes(nodes)
    {
        if (nodes.size() == 2 || nodes.size() == 3)
        {
            string str = "";
            for (auto node : nodes)
            {
                if (node.type == READ)
                {
                    str += "R";
                }
                else if (node.type == WRITE)
                {
                    str += "W";
                }
            } 
            if (str == "RW")
                patternType = RW;
            if (str == "WR")
                patternType = WR;
            if (str == "WW")
                patternType = WW;
            if (str == "RWR")
                patternType = RWR;
            if (str == "WWR")
                patternType = WWR;
            if (str == "WRW")
                patternType = WRW;
            if (str == "RWW")
                patternType = RWW;
            if (str == "WWW")
                patternType = WWW;
        } 
    }
};

inline std::ostream& operator<<(std::ostream& _out, ReadWriteNode rw)
{
    _out << rw.type << "Node: [ GID: " << rw.GID << ", selector: " << rw.selector
         << ", var: " << rw.var << " ]" << endl;
    return _out;
}

inline std::ostream& operator<<(std::ostream& _out, Pattern* pattern)
{
    _out << "Pattern { " << endl;
    for (auto node : pattern->nodes)
    {
        _out << "    ";
        _out << node.type << "Node: [ GID: " << node.GID << ", selector: " << node.selector
             << ", var: " << node.var << " ]" << endl;
    }
    _out << "}" << endl;
    return _out;
}

}  // namespace fuzzer