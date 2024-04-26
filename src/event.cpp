#include "agent/event.h"

std::ostream &operator<<(std::ostream &out, const Event &event)
{
    return out << "[" << event.index << "]\n\t" << event.eventname << " from " << event.pid << ":" << event.pname
               << "\n\t" << event.oname;
}