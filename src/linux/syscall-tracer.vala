namespace Frida {
	public sealed class SyscallTracer : Object {
		public uint pid {
			get;
			construct;
		}

		private Bpf.ArrayMap? target_tgid;

		private Bpf.RingbufReader? events_reader;
		private Source? events_source;

		private FileDescriptor? prog_fd;

		private Gee.Collection<PerfEvent.Monitor> monitors = new Gee.ArrayList<PerfEvent.Monitor> ();

		private static string?[] syscall_names;

		private const size_t RINGBUF_SIZE = 1U << 22;

		public SyscallTracer (uint pid) {
			Object (pid: pid);
		}

		static construct {
			var syscall_enum = (EnumClass) typeof (LinuxSyscall).class_ref ();

			var max_value = 0;
			for (uint i = 0; i != syscall_enum.n_values; i++) {
				var v = syscall_enum.values[i].value;
				if (v > max_value)
					max_value = v;
			}

			syscall_names = new string?[max_value + 1];

			for (uint i = 0; i != syscall_enum.n_values; i++) {
				var ev = syscall_enum.values[i];
				syscall_names[ev.value] = ev.value_nick.replace ("-", "_");
			}
		}

		protected override void dispose () {
			stop ();

			base.dispose ();
		}

		public void start () throws Error {
			target_tgid = new Bpf.ArrayMap (sizeof (uint32), 1);
			target_tgid.update_u32 (0, pid);

			var events = new Bpf.RingbufMap (RINGBUF_SIZE);
			events_reader = new Bpf.RingbufReader (events);

			Gum.ElfModule elf;
			try {
				var raw_elf = new Bytes.static (Frida.Data.HelperBackend.get_syscall_tracer_elf_blob ().data);
				elf = new Gum.ElfModule.from_blob (raw_elf);
			} catch (Gum.Error e) {
				assert_not_reached ();
			}

			var maps = new Gee.HashMap<string, Bpf.Map> ();
			maps["target_tgid"] = target_tgid;
			maps["events"] = events;

			prog_fd = Bpf.load_program_from_elf (TRACEPOINT, elf, "tracepoint/raw_syscalls/sys_enter", maps, "Dual BSD/GPL");

			uint32 tp_id = PerfEvent.get_tracepoint_id ("raw_syscalls", "sys_enter");

			uint ncpus = get_num_processors ();
			for (uint cpu = 0; cpu != ncpus; cpu++) {
				var pea = PerfEventAttr ();
				pea.event_type = TRACEPOINT;
				pea.size = (uint32) sizeof (PerfEventAttr);
				pea.config = tp_id;
				pea.sample_period = 1;

				var monitor = new PerfEvent.Monitor (&pea, -1, 0, -1, 0);
				if (cpu == 0)
					monitor.set_bpf (prog_fd);
				monitor.enable ();

				monitors.add (monitor);
			}

			var ch = new IOChannel.unix_new (events.fd.handle);
			var src = new IOSource (ch, IN);
			var state = new WatchState (this, events_reader);
			src.set_callback (state.on_ready);
			src.attach (MainContext.get_thread_default ());
			events_source = src;
		}

		public void stop () {
			events_source?.destroy ();
			events_source = null;

			foreach (var monitor in monitors) {
				try {
					monitor.disable ();
				} catch (Error e) {
					assert_not_reached ();
				}
			}
			monitors.clear ();

			prog_fd = null;
			events_reader = null;
			target_tgid = null;
		}

		private void handle_event (SyscallEvent * e) {
			var nr = (uint) e->syscall_nr;

			unowned string? name = null;
			if (nr < syscall_names.length)
				name = syscall_names[nr];

			printerr ("[SyscallTracer %p] sys=%u (%s) tgid=%u tid=%u time=%" + uint64.FORMAT + " depth=%u stack_err=%d\n",
				this, nr, (name != null) ? name : "?", e->tgid, e->tid, e->time_ns, e->depth, e->stack_err);
			//for (uint32 i = 0; i != e->depth; i++)
			//	printerr ("\t0x%lx\n", (ulong) e->ips[i]);
		}

		private struct SyscallEvent {
			public uint64 time_ns;
			public uint32 tgid;
			public uint32 tid;
			public int32 syscall_nr;
			public int32 stack_err;
			public uint32 depth;
			public uint64 ips[16];
		}

		private sealed class WatchState : Object {
			public unowned SyscallTracer tracer;
			public Bpf.RingbufReader reader;

			public WatchState (SyscallTracer tracer, Bpf.RingbufReader reader) {
				this.tracer = tracer;
				this.reader = reader;
			}

			public bool on_ready (IOChannel ch, IOCondition cond) {
				reader.drain ((payload, len) => {
					assert (len == sizeof (SyscallEvent));
					tracer.handle_event (payload);
				});
				return Source.CONTINUE;
			}
		}
	}
}
