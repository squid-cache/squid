#include "squid.h"
#include "acl/Tree.h"
#include "wordlist.h"

CBDATA_NAMESPACED_CLASS_INIT(Acl, Tree);

allow_t
Acl::Tree::winningAction() const
{
    return actionAt(lastMatch_ - nodes.begin());
}

allow_t
Acl::Tree::lastAction() const
{
    if (actions.empty())
        return ACCESS_DUNNO;
    return actions.back();
}

/// computes action that corresponds to the position of the matched rule
allow_t
Acl::Tree::actionAt(const Nodes::size_type pos) const
{
    assert(pos < nodes.size());
    if (actions.size()) {
        assert(actions.size() == nodes.size());
        return actions[pos];
    }
    // default for matched rules in trees without actions
    return ACCESS_ALLOWED;
}

void
Acl::Tree::add(ACL *rule, const allow_t &action)
{
    // either all rules have actions or none
    assert(nodes.size() == actions.size());
    InnerNode::add(rule);
    actions.push_back(action);
}

void
Acl::Tree::add(ACL *rule)
{
    // either all rules have actions or none
    assert(actions.empty());
    InnerNode::add(rule);
}

wordlist*
Acl::Tree::treeDump(const char *prefix, const ActionToString &convert) const
{
    wordlist *text = NULL;
    Actions::const_iterator action = actions.begin();
    typedef Nodes::const_iterator NCI;
    for (NCI node = nodes.begin(); node != nodes.end(); ++node) {

        wordlistAdd(&text, prefix);

        if (action != actions.end()) {
            const char *act = convert ? convert[action->kind] :
                              (*action == ACCESS_ALLOWED ? "allow" : "deny");
            wordlistAdd(&text, act ? act : "???");
            ++action;
        }

        wordlist *rule = (*node)->dump();
        wordlistAddWl(&text, rule);
        wordlistDestroy(&rule);

        wordlistAdd(&text, "\n");
    }
    return text;
}
