//! A singlethreaded libfuzzer-like fuzzer that can auto-restart.

use mimalloc::MiMalloc;
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use core::{cell::RefCell, time::Duration};
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::PathBuf,
    process,
    time::Instant,
};

use clap::{Arg, Command};
// TODO #[cfg(all(unix, feature = "std", feature = "fork"))]
use libafl::bolts::os::{fork, ForkResult};
use libafl::{
    bolts::{
        current_nanos, current_time,
        os::dup2,
        rands::StdRand,
        shmem::{ShMemProvider, StdShMemProvider},
        tuples::{tuple_list, Merge},
        AsSlice,
    },
    corpus::{Corpus, InMemoryOnDiskCorpus, OnDiskCorpus},
    events::{setup_restarting_mgr_std, EventConfig, EventRestarter, SimpleRestartingEventManager},
    executors::{inprocess::InProcessExecutor, ExitKind, TimeoutExecutor},
    feedback_and, feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, NewHashFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    monitors::{MultiMonitor, OnDiskTOMLMonitor, SimpleMonitor},
    mutators::{
        scheduled::havoc_mutations, token_mutations::I2SRandReplace, tokens_mutations,
        StdMOptMutator, StdScheduledMutator, Tokens,
    },
    observers::{BacktraceObserver, HitcountsMapObserver, TimeObserver},
    prelude::Rand,
    schedulers::{
        powersched::PowerSchedule, IndexesLenTimeMinimizerScheduler, StdWeightedScheduler,
    },
    stages::{
        calibrate::CalibrationStage, power::StdPowerMutationalStage, StdMutationalStage,
        TracingStage,
    },
    state::{HasCorpus, HasMetadata, StdState},
    Error,
};
#[cfg(any(target_os = "linux", target_vendor = "apple"))]
use libafl_targets::autotokens;
use libafl_targets::{
    libfuzzer_initialize, libfuzzer_test_one_input, std_edges_map_observer, CmpLogObserver,
};
use libc::{prctl, rlimit, setrlimit, PR_SET_DUMPABLE, RLIMIT_CORE};
#[cfg(unix)]
use nix::{self, unistd::dup};

/// The fuzzer main (as `no_mangle` C function)
#[no_mangle]
pub extern "C" fn libafl_main() {
    // Registry the metadata types used in this fuzzer
    // Needed only on no_std
    //RegistryBuilder::register::<Tokens>();

    let res = match Command::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author("AFLplusplus team")
        .about("LibAFL-based fuzzer for Fuzzbench")
        .arg(
            Arg::new("crashes")
                .short('o')
                .long("crashes_dir")
                .help("The directory to place finds in ('corpus')"),
        )
        .arg(
            Arg::new("in")
                .short('i')
                .long("input")
                .help("The directory to read initial inputs from ('seeds')"),
        )
        .arg(
            Arg::new("tokens")
                .short('x')
                .long("tokens")
                .help("A file to read tokens from, to be used during fuzzing"),
        )
        .arg(
            Arg::new("logfile")
                .short('l')
                .long("logfile")
                .help("Duplicates all output to this file")
                .default_value("libafl.log"),
        )
        .arg(
            Arg::new("statsfile")
                .short('s')
                .long("statsfile")
                .help("Writes stats to this file in toml format.")
                .default_value("fuzzerstats.toml"),
        )
        .arg(
            Arg::new("timeout")
                .short('t')
                .long("timeout")
                .help("Timeout for each individual execution, in milliseconds")
                .default_value("1200"),
        )
        .arg(
            // TODO: might need input byte size
            // Can have arg to where input shall be stored.
            Arg::new("findNonCrashingInput")
                .short('f')
                .long("findNonCrashingInput")
                .help("Find a non crashing input by randomly generating inputs.")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(Arg::new("remaining"))
        .try_get_matches()
    {
        Ok(res) => res,
        Err(err) => {
            println!(
                "Syntax: {}, [-x dictionary] -o corpus_dir -i seed_dir\n{:?}",
                env::current_exe()
                    .unwrap_or_else(|_| "fuzzer".into())
                    .to_string_lossy(),
                err,
            );
            return;
        }
    };

    println!(
        "Workdir: {:?}",
        env::current_dir().unwrap().to_string_lossy().to_string()
    );

    disable_core_dumps();

    if res.get_flag("findNonCrashingInput") {
        println!("Starting find for non-crashing input.");

        let args: Vec<String> = env::args().collect();

        let startTime = Instant::now();

        let mut found_non_crashing_input = false;
        let mut generated_inputs_count = 0;
        let mut rng = StdRand::with_seed(current_nanos());
        // TODO: set size, right now in 8 bytes
        const input_size: usize = 80;
        let mut buffer: [u64; input_size / 8] = [0; input_size / 8];

        while !found_non_crashing_input {
            if libfuzzer_initialize(&args) == -1 {
                println!("Warning: LLVMFuzzerInitialize failed with -1");
            }

            for i in 0..10 {
                buffer[i] = rng.next();
            }
            generated_inputs_count += 1;

            if generated_inputs_count % 51 == 50 {
                let elapsed_time = startTime.elapsed();
                println!(
                    "[FindNonCrashingInput] Generated {} inputs. {} fork/s",
                    generated_inputs_count,
                    generated_inputs_count as f64 / elapsed_time.as_secs_f64()
                );
            }

            match unsafe { fork() }.expect("Failed to fork.") {
                ForkResult::Parent(child) => {
                    // TODO wait for child, evaluate exit kind
                    // TODO: add timeout, after X seconds kill child, log, and contine
                    let child_exit_status = child.status();
                    let exited_with_signal = libc::WIFSIGNALED(child_exit_status);
                    if !exited_with_signal {
                        println!("Found non-crashing input.");
                        found_non_crashing_input = true;
                        // TODO: write input to file.
                    }
                }
                ForkResult::Child => unsafe {
                    libfuzzer_test_one_input(std::slice::from_raw_parts(
                        buffer.as_ptr() as *const u8,
                        input_size,
                    ));
                    std::process::exit(0);
                },
            }
        }

        // TODO: store buffer to file

        return;
    }

    if let Some(filenames) = res.get_many::<String>("remaining") {
        let filenames: Vec<&str> = filenames.map(String::as_str).collect();
        if !filenames.is_empty() {
            run_testcases(&filenames);
            return;
        }
    }

    // For fuzzbench, crashes and finds are inside the same `corpus` directory, in the "queue" and "crashes" subdir.
    let crashes_dir = PathBuf::from(
        res.get_one::<String>("crashes")
            .expect("The --crashes_dir parameter is missing")
            .to_string(),
    );
    if !crashes_dir.is_dir() {
        println!(
            "Crashes dir at {:?} is not a valid directory!",
            &crashes_dir
        );
        return;
    }

    let in_dir = PathBuf::from(
        res.get_one::<String>("in")
            .expect("The --input parameter is missing")
            .to_string(),
    );
    if !in_dir.is_dir() {
        println!("In dir at {:?} is not a valid directory!", &in_dir);
        return;
    }

    let tokens = res.get_one::<String>("tokens").map(PathBuf::from);

    let logfile = PathBuf::from(res.get_one::<String>("logfile").unwrap().to_string());
    let statsfile = PathBuf::from(res.get_one::<String>("statsfile").unwrap().to_string());

    let timeout = Duration::from_millis(
        res.get_one::<String>("timeout")
            .unwrap()
            .to_string()
            .parse()
            .expect("Could not parse timeout in milliseconds"),
    );

    fuzz(crashes_dir, &in_dir, tokens, &logfile, &statsfile, timeout)
        .expect("An error occurred while fuzzing");
}

fn disable_core_dumps() {
    unsafe {
        if prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            let err = std::io::Error::last_os_error();
            println!("Failed to disable core dumps: {}", err);
            return;
        }
    }
    println!("Core dumps disabled for this process.");
}

fn run_testcases(filenames: &[&str]) {
    // The actual target run starts here.
    // Call LLVMFUzzerInitialize() if present.
    let args: Vec<String> = env::args().collect();
    if libfuzzer_initialize(&args) == -1 {
        println!("Warning: LLVMFuzzerInitialize failed with -1");
    }

    println!(
        "You are not fuzzing, just executing {} testcases",
        filenames.len()
    );
    for fname in filenames {
        println!("Executing {fname}");

        let mut file = File::open(fname).expect("No file found");
        let mut buffer = vec![];
        file.read_to_end(&mut buffer).expect("Buffer overflow");

        libfuzzer_test_one_input(&buffer);
    }
}

/// The actual fuzzer
#[allow(clippy::too_many_lines)]
fn fuzz(
    crashes_dir: PathBuf,
    seed_dir: &PathBuf,
    tokenfile: Option<PathBuf>,
    logfile: &PathBuf,
    statsfile: &PathBuf,
    timeout: Duration,
) -> Result<(), Error> {
    let log = RefCell::new(OpenOptions::new().append(true).create(true).open(logfile)?);

    #[cfg(unix)]
    let mut stdout_cpy = unsafe {
        let new_fd = dup(io::stdout().as_raw_fd())?;
        File::from_raw_fd(new_fd)
    };
    #[cfg(unix)]
    let file_null = File::open("/dev/null")?;

    // 'While the monitor are state, they are usually used in the broker - which is likely never restarted
    let monitor = SimpleMonitor::new(|s| {
        #[cfg(unix)]
        writeln!(&mut stdout_cpy, "{s}").unwrap();
        #[cfg(windows)]
        println!("{s}");
        writeln!(log.borrow_mut(), "{:?} {s}", current_time()).unwrap();
    });
    /*let monitor = OnDiskTOMLMonitor::new(
        statsfile,
        MultiMonitor::new(|s| println!("{s}")),
    );*/

    // We need a shared map to store our state before a crash.
    // This way, we are able to continue fuzzing afterwards.
    let mut shmem_provider = StdShMemProvider::new()?;

    let (state, mut restarting_mgr) =
        match SimpleRestartingEventManager::launch(monitor, &mut shmem_provider) {
            // The restarting state will spawn the same process again as child, then restarted it each time it crashes.
            Ok(res) => res,
            Err(err) => match err {
                Error::ShuttingDown => {
                    return Ok(());
                }
                _ => {
                    panic!("Failed to setup the restarter: {err}");
                }
            },
        };

    // let broker_port = 1337;

    // let (state, mut restarting_mgr) =
    //     match setup_restarting_mgr_std(monitor, broker_port, EventConfig::AlwaysUnique) {
    //         Ok(res) => res,
    //         Err(err) => match err {
    //             Error::ShuttingDown => {
    //                 return Ok(());
    //             }
    //             _ => {
    //                 panic!("Failed to setup the restarter: {err}");
    //             }
    //         },
    //     };

    // Create an observation channel using the coverage map
    // We don't use the hitcounts (see the Cargo.toml, we use pcguard_edges)
    let edges_observer = HitcountsMapObserver::new(unsafe { std_edges_map_observer("edges") });

    // Create an observation channel to keep track of the execution time
    let time_observer = TimeObserver::new("time");

    let cmplog_observer = CmpLogObserver::new("cmplog", true);

    let map_feedback = MaxMapFeedback::tracking(&edges_observer, true, false);

    let calibration = CalibrationStage::new(&map_feedback);

    // Feedback to rate the interestingness of an input
    // This one is composed by two Feedbacks in OR
    let mut feedback = feedback_or!(
        // New maximization map feedback linked to the edges observer and the feedback state
        map_feedback,
        // Time feedback, this one does not need a feedback state
        TimeFeedback::with_observer(&time_observer)
    );

    let mut bt = None;
    let bt_observer = BacktraceObserver::new(
        "BacktraceObserver",
        &mut bt,
        libafl::observers::HarnessType::InProcess,
    );

    // A feedback to choose if an input is a solution or not
    let mut objective = feedback_and!(CrashFeedback::new(), NewHashFeedback::new(&bt_observer));

    // If not restarting, create a State from scratch
    let mut state = state.unwrap_or_else(|| {
        StdState::new(
            // RNG
            StdRand::with_seed(current_nanos()),
            // Corpus that will be evolved, we keep it in memory for performance
            InMemoryOnDiskCorpus::new(seed_dir).unwrap(),
            // Corpus in which we store solutions (crashes in this example),
            // on disk so the user can get them after stopping the fuzzer
            OnDiskCorpus::new(crashes_dir).unwrap(),
            // States of the feedbacks.
            // The feedbacks can report the data that should persist in the State.
            &mut feedback,
            // Same for objective feedbacks
            &mut objective,
        )
        .unwrap()
    });

    println!("Let's fuzz :)");

    // The actual target run starts here.
    // Call LLVMFUzzerInitialize() if present.
    let args: Vec<String> = env::args().collect();
    if libfuzzer_initialize(&args) == -1 {
        println!("Warning: LLVMFuzzerInitialize failed with -1");
    }

    // Setup a randomic Input2State stage
    let i2s = StdMutationalStage::new(StdScheduledMutator::new(tuple_list!(I2SRandReplace::new())));

    // Setup a MOPT mutator
    let mutator = StdMOptMutator::new(
        &mut state,
        havoc_mutations().merge(tokens_mutations()),
        7,
        5,
    )?;

    let power = StdPowerMutationalStage::new(mutator);

    // A minimization+queue policy to get testcasess from the corpus
    let scheduler = IndexesLenTimeMinimizerScheduler::new(StdWeightedScheduler::with_schedule(
        &mut state,
        &edges_observer,
        Some(PowerSchedule::FAST),
    ));

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // The wrapped harness function, calling out to the LLVM-style harness
    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let buf = target.as_slice();
        libfuzzer_test_one_input(buf);
        ExitKind::Ok
    };

    let mut tracing_harness = harness;

    // Create the executor for an in-process function with one observer for edge coverage and one for the execution time
    let mut executor = TimeoutExecutor::new(
        InProcessExecutor::new(
            &mut harness,
            tuple_list!(edges_observer, time_observer, bt_observer),
            &mut fuzzer,
            &mut state,
            &mut restarting_mgr,
        )?,
        timeout,
    );

    // Setup a tracing stage in which we log comparisons
    let tracing = TracingStage::new(TimeoutExecutor::new(
        InProcessExecutor::new(
            &mut tracing_harness,
            tuple_list!(cmplog_observer),
            &mut fuzzer,
            &mut state,
            &mut restarting_mgr,
        )?,
        // Give it more time!
        timeout * 10,
    ));

    // The order of the stages matter!
    let mut stages = tuple_list!(calibration, tracing, i2s, power);

    // Read tokens
    if state.metadata_map().get::<Tokens>().is_none() {
        let mut toks = Tokens::default();
        if let Some(tokenfile) = tokenfile {
            toks.add_from_file(tokenfile)?;
        }
        #[cfg(any(target_os = "linux", target_vendor = "apple"))]
        {
            toks += autotokens()?;
        }

        if !toks.is_empty() {
            state.add_metadata(toks);
        }
    }

    // In case the corpus is empty (on first run), reset
    if state.must_load_initial_inputs() {
        state
            .load_initial_inputs(
                &mut fuzzer,
                &mut executor,
                &mut restarting_mgr,
                &[seed_dir.clone()],
            )
            .unwrap_or_else(|_| {
                println!("Failed to load initial corpus at {:?}", &seed_dir);
                process::exit(0);
            });
        println!("We imported {} inputs from disk.", state.corpus().count());
    }

    // Remove target ouput (logs still survive)
    // TODO: uncomment again #[cfg(unix)]
    // TODO: uncomment again {
    // TODO: uncomment again     let null_fd = file_null.as_raw_fd();
    // TODO: uncomment again     dup2(null_fd, io::stdout().as_raw_fd())?;
    // TODO: uncomment again     dup2(null_fd, io::stderr().as_raw_fd())?;
    // TODO: uncomment again }
    // reopen file to make sure we're at the end
    log.replace(OpenOptions::new().append(true).create(true).open(logfile)?);

    let iters = 1_000_000;
    fuzzer.fuzz_loop_for(
        &mut stages,
        &mut executor,
        &mut state,
        &mut restarting_mgr,
        iters,
    )?;

    restarting_mgr.on_restart(&mut state)?;

    // Never reached
    Ok(())
}
