
import sys
import argparse
import config
from hmais.orchestrator import HMAISOrchestrator
from hmais.tools.investigation_state import load_state, save_state, format_investigation_summary
from log_fmt_new import main_formatter
import threading

# python main.py --poi "8D401053-39B3-11E8-BF66-D9AA8AFF4A69"

def main():
    
    parser = argparse.ArgumentParser(
        description="HMAIS - 假设驱动的多智能体攻击调查系统"
    )
    parser.add_argument(
        "--poi",
        type=str,
        default=None,
        help="初始调查点 (POI) - 可疑事件的 UUID"
    )
    parser.add_argument(
        "--continue",
        dest="continue_session",
        type=str,
        help="继续调查的会话目录路径（如 logs/20260127_135152）"
    )
    parser.add_argument(
        "--correct",
        dest="correct_session",
        type=str,
        help="纠错的会话目录路径（如 logs/20260127_135152）"
    )
    parser.add_argument(
        "--feedback",
        type=str,
        help="纠错反馈（自然语言描述，如'bash 进程不是恶意的'）"
    )
    parser.add_argument(
        "--direction",
        type=str,
        help="人类安全员的调查方向指导（自然语言描述）"
    )
    args = parser.parse_args()

    try:

        if args.correct_session:
            print(f"\n{'='*60}")
            print("🔧 纠错模式")
            print(f"{'='*60}")
            
            if not args.feedback:
                print("❌ 纠错模式需要 --feedback 参数")
                return 1
            
            state = load_state(args.correct_session)
            if not state:
                print("❌ 无法加载调查状态，请检查路径是否正确")
                return 1
            
            print(format_investigation_summary(state))
            
            from hmais.agents.correction_agent import CorrectionAgent, save_corrected_state
            
            correction_agent = CorrectionAgent()
            corrected_state, new_direction = correction_agent.correct(
                state=state,
                feedback=args.feedback,
                human_direction=args.direction
            )
            
            corrected_path = save_corrected_state(args.correct_session, corrected_state)
            
            poi = corrected_state.get("poi", {}).get("event_id", "")
            if not poi:
                print("❌ 状态中未找到 POI 信息")
                return 1
            
            orchestrator = HMAISOrchestrator()
            
            orchestrator.restore_state(corrected_state)
            
            if new_direction:
                orchestrator.set_human_direction(new_direction)
            
            print(f"\n{'='*60}")
            print(f"🔍 纠错后继续调查: {poi}")
            print(f"{'='*60}")
            orchestrator.run_investigation(initial_poi=poi, is_continuation=True)
        
        elif args.continue_session:
            print(f"\n{'='*60}")
            print("📂 继续调查模式")
            print(f"{'='*60}")
            
            state = load_state(args.continue_session)
            if not state:
                print("❌ 无法加载调查状态，请检查路径是否正确")
                return 1
            
            print(format_investigation_summary(state))
            
            poi = state.get("poi", {}).get("event_id", "")
            if not poi:
                print("❌ 状态中未找到 POI 信息")
                return 1
            
            orchestrator = HMAISOrchestrator()
            orchestrator.restore_state(state)
            
            if args.direction:
                orchestrator.set_human_direction(args.direction)
            
            print(f"\n{'='*60}")
            print(f"🔍 继续调查: {poi}")
            print(f"{'='*60}")
            t1 = threading.Thread(target=orchestrator.run_investigation, kwargs={"initial_poi": poi, "is_continuation": True})
            t2 = threading.Thread(target=main_formatter, args=(config.FORMATTER_KEYS, poi))
            t1.start(); t2.start()
            t1.join(); t2.join()
        else:

            if not args.poi:
                print("❌ 新调查模式需要 --poi 参数（事件 UUID）")
                return 1
            
            orchestrator = HMAISOrchestrator()
            t1 = threading.Thread(target=orchestrator.run_investigation, kwargs={"initial_poi": args.poi})
            t2 = threading.Thread(target=main_formatter, args=(config.FORMATTER_KEYS, args.poi))
            t1.start(); t2.start()
            t1.join(); t2.join()

        print("\n✓ 调查演示完成！")
        return 0

    except KeyboardInterrupt:
        print("\n\n⚠️  用户中断调查")
        return 1
    except Exception as e:
        print(f"\n\n❌ 调查过程中出错: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
   