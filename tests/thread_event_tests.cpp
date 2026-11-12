// Thread-event callback chain semantics: release, blocking, and reentrancy.
#include "kernel/thread_event_dispatch.hpp"

#include <cstdio>
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace {
int failures = 0;
void check(bool ok, const char *label) {
    std::printf("%s %s\n", ok ? "ok  " : "FAIL", label);
    if (!ok) ++failures;
}
struct Context { std::vector<std::string> trace; };
struct Handler { int id{}; };
using Handlers = std::map<int, Handler>;
using Continue = std::function<void(Context &)>;

void release_pending_handler() {
    Handlers handlers{{1,{1}}, {2,{2}}, {3,{3}}};
    Context context;
    portablekit::dispatch_thread_event_chain(handlers, std::vector<int>{1,2,3}, context,
        [&handlers](Context &ctx, const Handler &h, Continue next) {
            ctx.trace.push_back("handler-" + std::to_string(h.id));
            if (h.id == 1) handlers.erase(2); // released before its turn
            next(ctx);
        }, [](Context &ctx) { ctx.trace.push_back("complete"); });
    check(context.trace == std::vector<std::string>{"handler-1","handler-3","complete"},
          "a handler released by an earlier callback is skipped");
}

void release_self() {
    Handlers handlers{{1,{1}}, {2,{2}}};
    Context context;
    portablekit::dispatch_thread_event_chain(handlers, std::vector<int>{1,2}, context,
        [&handlers](Context &ctx, const Handler &h, Continue next) {
            ctx.trace.push_back("handler-" + std::to_string(h.id));
            if (h.id == 1) handlers.erase(1);
            next(ctx);
        }, [](Context &ctx) { ctx.trace.push_back("complete"); });
    check(context.trace == std::vector<std::string>{"handler-1","handler-2","complete"} &&
          handlers.count(1) == 0, "a running handler may release itself safely");
}

void blocked_handler_then_release() {
    Handlers handlers{{1,{1}}, {2,{2}}};
    Context context;
    Continue resume;
    portablekit::dispatch_thread_event_chain(handlers, std::vector<int>{1,2}, context,
        [&handlers,&resume](Context &ctx, const Handler &h, Continue next) {
            ctx.trace.push_back("handler-" + std::to_string(h.id));
            if (h.id == 1) resume = std::move(next); // guest callback blocks
            else next(ctx);
        }, [](Context &ctx) { ctx.trace.push_back("complete"); });
    check(context.trace == std::vector<std::string>{"handler-1"} && bool(resume),
          "a blocking callback suspends the remaining chain");
    handlers.erase(2);
    resume(context); // resumed guest callback returns after handler 2 was released
    check(context.trace == std::vector<std::string>{"handler-1","complete"},
          "a released handler is skipped when a blocked callback resumes");
}

void nested_dispatch() {
    Handlers handlers{{1,{1}}, {2,{2}}};
    Context context;
    portablekit::dispatch_thread_event_chain(handlers, std::vector<int>{1}, context,
        [&handlers](Context &ctx, const Handler &h, Continue outer_next) {
            ctx.trace.push_back("outer-start");
            portablekit::dispatch_thread_event_chain(handlers, std::vector<int>{2}, ctx,
                [&ctx](Context &nested, const Handler &, Continue nested_next) {
                    nested.trace.push_back("nested-handler");
                    nested_next(nested);
                }, [&outer_next](Context &nested) {
                    nested.trace.push_back("nested-complete");
                    outer_next(nested);
                });
            ctx.trace.push_back("outer-return");
        }, [](Context &ctx) { ctx.trace.push_back("outer-complete"); });
    check(context.trace == std::vector<std::string>{
              "outer-start","nested-handler","nested-complete","outer-complete","outer-return"},
          "nested event dispatch completes without corrupting the outer callback chain");
}
} // namespace

int main() {
    release_pending_handler();
    release_self();
    blocked_handler_then_release();
    nested_dispatch();
    return failures == 0 ? 0 : 1;
}
