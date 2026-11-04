// The page's side of an engine worker: starts it, forwards its events, restarts it (to
// cancel a search, or after a crash), and for as-you-type tools keeps one request in flight,
// sending only the latest text once the worker is free.

type WithId = { id: number };
type Event = { type: string; id?: number | null };

export class EngineClient<Req extends WithId, Ev extends Event> {
  private worker: Worker | null = null;
  private readonly listeners = new Set<(event: Ev) => void>();

  constructor(
    private readonly create: () => Worker,
    private readonly name: string,
  ) {}

  /** Starts the worker if it isn't running (it loads its WebAssembly module right away). */
  start(): void {
    if (this.worker) return;
    const worker = this.create();
    worker.onmessage = (e: MessageEvent<Ev>) => this.emit(e.data);
    worker.onerror = (e: ErrorEvent) => {
      e.preventDefault();
      this.emit({ type: "error", id: null, message: `${this.name} stopped: ${e.message || "the worker failed to start"}` } as unknown as Ev);
    };
    this.worker = worker;
  }

  post(request: Req): void {
    this.start();
    this.worker?.postMessage(request);
  }

  /** Stops the worker (and whatever it was doing) and starts a fresh one. */
  restart(): void {
    this.worker?.terminate();
    this.worker = null;
    this.start();
  }

  on(listener: (event: Ev) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private emit(event: Ev): void {
    for (const l of this.listeners) l(event);
  }
}

/**
 * Latest-wins requests for as-you-type tools: while one request is with the worker, newer
 * ones replace each other, and only the last is sent when the reply comes. So a slow text
 * never queues up stale work behind it.
 */
export class LatestRequest<Req extends WithId> {
  private nextId = 1;
  private inFlight: number | null = null;
  private waiting: Req | null = null;

  constructor(private readonly send: (request: Req) => void) {}

  /** Queues `make(id)`; returns its id. */
  request(make: (id: number) => Req): number {
    const req = make(this.nextId++);
    if (this.inFlight === null) {
      this.inFlight = req.id;
      this.send(req);
    } else {
      this.waiting = req;
    }
    return req.id;
  }

  /**
   * Call with the id of every reply (or error). Returns whether it answers the newest request,
   * i.e. whether the page should show it.
   */
  settle(id: number | null | undefined): boolean {
    if (id !== this.inFlight) return false;
    this.inFlight = null;
    if (this.waiting) {
      const next = this.waiting;
      this.waiting = null;
      this.inFlight = next.id;
      this.send(next);
      return false;
    }
    return true;
  }

  /** Forgets everything in flight (after the worker restarted). */
  reset(): void {
    this.inFlight = null;
    this.waiting = null;
  }
}
