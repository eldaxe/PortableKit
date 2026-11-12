#pragma once

#include <functional>
#include <utility>
#include <vector>

namespace portablekit {

// Dispatches a snapshot of handler IDs, resolving each ID immediately before
// invocation. The continuation models a guest callback return: it may be
// retained while the guest blocks, invoked after a nested dispatch, or skipped
// when a handler has been released before its turn.
template <typename HandlerMap, typename Context, typename Invoke, typename Complete>
void dispatch_thread_event_chain(HandlerMap &handlers,
                                 const std::vector<typename HandlerMap::key_type> &snapshot,
                                 Context &context, Invoke invoke,
                                 Complete on_complete) {
    std::function<void(Context &)> chain = std::move(on_complete);
    for (auto it = snapshot.rbegin(); it != snapshot.rend(); ++it) {
        const auto handler_id = *it;
        auto previous = std::move(chain);
        chain = [&handlers, handler_id, invoke, previous = std::move(previous)]
                (Context &current) mutable {
            const auto found = handlers.find(handler_id);
            if (found == handlers.end()) {
                if (previous) previous(current);
                return;
            }
            // Copy before entering guest code: that code may release itself.
            const auto handler = found->second;
            invoke(current, handler, std::move(previous));
        };
    }
    if (chain) chain(context);
}

} // namespace portablekit
