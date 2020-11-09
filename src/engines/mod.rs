use crate::corpus::testcase::{Testcase, TestcaseMetadata};
use crate::corpus::Corpus;
use crate::executors::Executor;
use crate::feedbacks::Feedback;
use crate::inputs::Input;
use crate::stages::Stage;
use crate::AflError;

use std::cell::RefCell;
use std::rc::Rc;

pub trait Evaluator<I>
where
    I: Input,
{
    fn evaluate_input(
        &mut self,
        input: &mut I,
        entry: Rc<RefCell<Testcase<I>>>,
    ) -> Result<bool, AflError>;
}

pub trait Engine<I, C, E>: Evaluator<I>
where
    I: Input,
    C: Corpus<I>,
    E: Executor<I>,
{
    fn feedbacks(&self) -> &Vec<Box<dyn Feedback<I>>>;

    fn feedbacks_mut(&mut self) -> &mut Vec<Box<dyn Feedback<I>>>;

    fn add_feedback(&mut self, feedback: Box<dyn Feedback<I>>) {
        self.feedbacks_mut().push(feedback);
    }

    fn stages(&self) -> &Vec<Box<dyn Stage<I, E = Self>>>;

    fn stages_mut(&mut self) -> &mut Vec<Box<dyn Stage<I, E = Self>>>;

    fn add_stage(&mut self, stage: Box<dyn Stage<I, E = Self>>) {
        self.stages_mut().push(stage);
    }

    fn corpus(&self) -> &C;

    fn corpus_mut(&mut self) -> &mut C;

    fn executor(&self) -> &E;

    fn executor_mut(&mut self) -> &mut E;

    fn fuzz_one(&mut self) -> Result<(), AflError> {
        if self.corpus().count() == 0 {
            return Err(AflError::Empty("No testcases in corpus".to_owned()));
        }
        let entry = self.corpus_mut().next()?;
        for stage in self.stages_mut() {
            stage.perform(&entry)?;
        }
        Ok(())
    }

    fn evaluate_input_engine(
        &mut self,
        input: &mut I,
        _entry: Rc<RefCell<Testcase<I>>>,
    ) -> Result<bool, AflError> {
        self.executor_mut().reset_observers()?;
        self.executor_mut().run_target(input)?;
        self.executor_mut().post_exec_observers()?;

        let mut metadatas: Vec<Box<dyn TestcaseMetadata>> = vec![];
        let mut rate_acc = 0;
        for feedback in self.feedbacks_mut() {
            let (rate, meta) = feedback.is_interesting(input);
            rate_acc += rate;
            if let Some(m) = meta {
                metadatas.push(m);
            }
        }

        if rate_acc >= 25 {
            let new_entry = Rc::new(RefCell::new(Testcase::<I>::new(input.clone())));
            for meta in metadatas {
                new_entry.borrow_mut().add_metadata(meta);
            }
            self.corpus_mut().add(new_entry);

            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/*
pub struct FuzzState<I, C, E>
where
    I: Input,
    C: Corpus<I>,
    E: Executor<I>,
{

}
*/



pub struct DefaultEngine<I, C, E>
where
    I: Input,
    C: Corpus<I>,
    E: Executor<I>,
{
    feedbacks: Vec<Box<dyn Feedback<I>>>,
    stages: Vec<Box<dyn Stage<I, E = Self>>>,
    executor: E,
    corpus: C,
}

impl<I, C, E> Evaluator<I> for DefaultEngine<I, C, E>
where
    I: Input,
    C: Corpus<I>,
    E: Executor<I>,
{
    fn evaluate_input(
        &mut self,
        input: &mut I,
        entry: Rc<RefCell<Testcase<I>>>,
    ) -> Result<bool, AflError> {
        self.evaluate_input_engine(input, entry)
    }
}

impl<I, C, E> Engine<I, C, E> for DefaultEngine<I, C, E>
where
    I: Input,
    C: Corpus<I>,
    E: Executor<I>,
{
    fn feedbacks(&self) -> &Vec<Box<dyn Feedback<I>>> {
        &self.feedbacks
    }

    fn feedbacks_mut(&mut self) -> &mut Vec<Box<dyn Feedback<I>>> {
        &mut self.feedbacks
    }

    fn stages(&self) -> &Vec<Box<dyn Stage<I, E = Self>>> {
        &self.stages
    }

    fn stages_mut(&mut self) -> &mut Vec<Box<dyn Stage<I, E = Self>>> {
        &mut self.stages
    }

    fn corpus(&self) -> &C {
        &self.corpus
    }

    fn corpus_mut(&mut self) -> &mut C {
        &mut self.corpus
    }

    fn executor(&self) -> &E {
        &self.executor
    }

    fn executor_mut(&mut self) -> &mut E {
        &mut self.executor
    }
}

impl<I, C, E> DefaultEngine<I, C, E>
where
    I: Input,
    C: Corpus<I>,
    E: Executor<I>,
{
    pub fn new(corpus: C, executor: E) -> Self {
        DefaultEngine {
            feedbacks: vec![],
            stages: vec![],
            corpus: corpus,
            executor: executor,
        }
    }

    pub fn new_rr(corpus: C, executor: E) -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Self::new(corpus, executor)))
    }
}

#[cfg(test)]
mod tests {
    use crate::corpus::{Corpus, InMemoryCorpus, Testcase};
    use crate::engines::{DefaultEngine, Engine};
    use crate::executors::inmemory::InMemoryExecutor;
    use crate::executors::{Executor, ExitKind};
    use crate::inputs::bytes::BytesInput;
    use crate::stages::mutational::DefaultMutationalStage;
    use crate::mutators::DefaultScheduledMutator;
    use crate::stages::Stage;
    use crate::utils::Xoshiro256StarRand;

    fn harness<I>(_executor: &dyn Executor<I>, _buf: &[u8]) -> ExitKind {
        ExitKind::Ok
    }

    #[test]
    fn test_engine() {
        let rand = Xoshiro256StarRand::preseeded_rr();

        let mut corpus = InMemoryCorpus::<BytesInput, _>::new(&rand);
        let testcase = Testcase::new_rr(BytesInput::new(vec![0; 4]));
        corpus.add(testcase);
        let executor = InMemoryExecutor::new(harness);
        let engine = DefaultEngine::new_rr(corpus, executor);
        //let mutator = DefaultScheduledMutator::new_all(rand: &rand, corpus: Option<Box<C>>, mutations: Vec<MutationFunction<Self, I>>)(&rand);
        //let stage = DefaultMutationalStage::new(&rand, &engine, mutator);
        //engine.borrow_mut().add_stage(Box::new(stage));
        engine.borrow_mut().fuzz_one().unwrap();
        let t = { engine.borrow_mut().corpus_mut().next().unwrap() };
        //engine.borrow_mut().stages[0].perform(&t).unwrap();
    }
}
