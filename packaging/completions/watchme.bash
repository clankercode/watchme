# bash completion for watchme (practical subset)
_watchme() {
  local cur prev
  COMPREPLY=()
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"
  local cmds="hooks status list explain snapshot logs stop pause resume doctor providers config daemon help"
  case "${COMP_CWORD}" in
    1)
      COMPREPLY=( $(compgen -W "${cmds}" -- "${cur}") )
      ;;
    2)
      case "${prev}" in
        hooks) COMPREPLY=( $(compgen -W "install-claude remove-claude" -- "${cur}") ) ;;
        config) COMPREPLY=( $(compgen -W "path check show" -- "${cur}") ) ;;
        daemon) COMPREPLY=( $(compgen -W "run status stop" -- "${cur}") ) ;;
        stop) COMPREPLY=( $(compgen -W "--all --json" -- "${cur}") ) ;;
        doctor) COMPREPLY=( $(compgen -W "--strict --json" -- "${cur}") ) ;;
      esac
      ;;
  esac
}
complete -F _watchme watchme
complete -F _watchme WatchMe
